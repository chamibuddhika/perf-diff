/*
 * perf-diff -- Capture micro-achitectural event diffs.
 * <http://github.com/chamibuddhika/perf-diff>
 *
 * Copyright (c) 2019 Buddhika Chamith
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Date : 10/18/2019
 */

#ifndef PERF_H_
#define PERF_H_

#include <asm/unistd.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ALLOC_N(type, n) ((type*)malloc(sizeof(type) * n))
#define ALLOC(type) ALLOC_N(type, 1)

// RAII style cleanup for C.
static inline void free_ptr(void* p) { free(*(void**)p); }
#define CLEANUP __attribute__((__cleanup__(free_ptr)))

static inline long __perf_event_open(struct perf_event_attr* hw_event,
                                     pid_t pid, int cpu, int group_fd,
                                     unsigned long flags) {
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

typedef struct __read_format {
  uint64_t nr;
  uint64_t time_enabled;  // PERF_FORMAT_TOTAL_TIME_ENABLED.
  uint64_t time_running;  // PERF_FORMAT_TOTAL_TIME_RUNNING.
  struct {
    uint64_t value;  // The value of the event.
    uint64_t id;     // PERF_FORMAT_ID.
  } values[];
} __read_format;

typedef struct __perf_event {
  const char* name;  // perf list event name.
  uint64_t config;   // perf_event_attr.config.
  uint32_t type;     // perf_event_attr.type.
  bool pinned;       // If this event should be pinned to the core.
  bool fixed;        // If this is a hardware event counted by fixed PMCs.
} __perf_event;

typedef struct __perf_event_list {
  size_t n_events;
  __perf_event* events;
} __perf_event_list;

void free_perf_event_list(__perf_event_list* ls) {
  free(ls->events);
  free(ls);
}

typedef struct __perf_event_group {
  size_t n_events;
  __perf_event* leader;   // Leader event. May or may not be pinned.
  __perf_event** events;  // All events inlcuding the leader.

  int leader_fd;
  uint64_t* event_ids;
} __perf_event_group;

typedef struct __perf_event_group_list {
  int n_groups;
  __perf_event_group* groups;
} __perf_event_group_list;

void free_perf_event_group_list(__perf_event_group_list* gls) {
  for (size_t i = 1; i < gls->n_groups; i++) {
    free(gls->groups[i].events);
  }
  free(gls);
}

typedef struct __perf_handle {
  const __perf_event_group_list* gls;

  char* argv;
  size_t argv_sz;
} __perf_handle;

typedef struct __cpuid {
  int eax;
  int ebx;
  int ecx;
  int edx;
} __cpuid;

typedef struct __pmc_info {
  int fixed;
  int programmable;
} __pmc_info;

#define CACHE_CONFIG(cache_id, op_id, result_id)                               \
  (cache_id) | (op_id << 8) | (result_id << 16)

static inline __attribute__((always_inline)) void __get_cpuid(int mode,
                                                              __cpuid* id) {
  asm volatile("cpuid"
               : "=a"(id->eax), "=b"(id->ebx), "=c"(id->ecx), "=d"(id->edx)
               : "a"(mode), "c"(0));
}

static __pmc_info* __get_pmc_info() {
  __cpuid id = {0};
  __get_cpuid(0x0A /* PMU */, &id);

  // As per SDM (Ch. 18)
  //
  // CPUID.0AH.EAX[7:0]  = version id
  // CPUID.0AX.EAX[15:8] = # of programmable MSRs per logical processor
  // CPUID.0AX.EDX[4:0]  = # of fixed MSRs per logical processor
  if ((id.eax & 0xFF) > 0) {
    __pmc_info* info = ALLOC(__pmc_info);
    info->programmable = (id.eax >> 8) & 0xFF;
    info->fixed = id.edx & 0xF;
    return info;
  }
  return NULL;
}

static const char* __trim(char* str) {
  char* end;
  // Trim leading spaces.
  while (isspace((unsigned char)*str)) {
    str++;
  }

  if (*str == '\0') {  // All spaces.
    return str;
  }

  // Trim trailing spaces.
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) {
    end--;
  }

  end[1] = '\0';
  return str;
}

static bool __update_event_config(__perf_event* event, __perf_event_list* ls,
                                  size_t n_events) {
  for (size_t i = 0; i < n_events; i++) {
    char* dup CLEANUP = strdup(event->name);
    if (!strcmp(__trim(dup), ls->events[i].name)) {
      free((void*)event->name);

      event->name = strdup(ls->events[i].name);
      event->config = ls->events[i].config;
      event->type = ls->events[i].type;
      event->pinned = ls->events[i].pinned;
      event->fixed = ls->events[i].fixed;
      return true;
    }
  }
  return false;
}

static __perf_event_list* __get_perf_event_list() {
  __perf_event events[] = {
      /* perf_event_open(2) PERF_TYPE_HARDWARE type events */
      {.name = "cycles",
       .config = PERF_COUNT_HW_CPU_CYCLES,
       .type = PERF_TYPE_HARDWARE,
       .pinned = true,
       .fixed = true},
      {.name = "instructions",
       .config = PERF_COUNT_HW_INSTRUCTIONS,
       .type = PERF_TYPE_HARDWARE,
       .pinned = true,
       .fixed = true},
      {.name = "cache-references",
       .config = PERF_COUNT_HW_CACHE_REFERENCES,
       .type = PERF_TYPE_HARDWARE},
      {.name = "cache-misses",
       .config = PERF_COUNT_HW_CACHE_MISSES,
       .type = PERF_TYPE_HARDWARE},
      {.name = "branches",
       .config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
       .type = PERF_TYPE_HARDWARE},
      {.name = "branch-misses",
       .config = PERF_COUNT_HW_BRANCH_MISSES,
       .type = PERF_TYPE_HARDWARE},
      {.name = "bus-cycles",
       .config = PERF_COUNT_HW_BUS_CYCLES,
       .type = PERF_TYPE_HARDWARE},
      {.name = "frontend-stalls",
       .config = PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
       .type = PERF_TYPE_HARDWARE},
      {.name = "backend-stalls",
       .config = PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
       .type = PERF_TYPE_HARDWARE},
      {.name = "ref-cycles",
       .config = PERF_COUNT_HW_REF_CPU_CYCLES,
       .type = PERF_TYPE_HARDWARE,
       .pinned = true,
       .fixed = true},

      /* perf_event_open(2) PERF_TYPE_SOFTWARE type events */
      {.name = "cpu-clock",
       .config = PERF_COUNT_SW_CPU_CLOCK,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "task-clock",
       .config = PERF_COUNT_SW_TASK_CLOCK,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "page-faults",
       .config = PERF_COUNT_SW_PAGE_FAULTS,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "context-switches",
       .config = PERF_COUNT_SW_CONTEXT_SWITCHES,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "cpu-migrations",
       .config = PERF_COUNT_SW_CPU_MIGRATIONS,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "minor-faults",
       .config = PERF_COUNT_SW_PAGE_FAULTS_MIN,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "major-faults",
       .config = PERF_COUNT_SW_PAGE_FAULTS_MAJ,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "alignment-faults",
       .config = PERF_COUNT_SW_ALIGNMENT_FAULTS,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "emulation-faults",
       .config = PERF_COUNT_SW_EMULATION_FAULTS,
       .type = PERF_TYPE_SOFTWARE},
      {.name = "dummy",
       .config = PERF_COUNT_SW_DUMMY,
       .type = PERF_TYPE_SOFTWARE},

      /* perf_event_open(2) PERF_TYPE_HW_CACHE type events */
      {.name = "L1-dcache-load-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "L1-dcache-loads",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "L1-dcache-stores",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_WRITE,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "L1-icache-stores",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "LLC-load-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "LLC-loads",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "LLC-store-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_WRITE,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "LLC-stores",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_WRITE,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "branch-load-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_BPU, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "branch-loads",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_BPU, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "dTLB-load-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "dTLB-loads",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "dTLB-store-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_WRITE,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "dTLB-stores",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_WRITE,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "iTLB-load-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_ITLB, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "iTLB-loads",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_ITLB, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "node-load-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_NODE, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "node-loads",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_NODE, PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "node-store-misses",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_NODE, PERF_COUNT_HW_CACHE_OP_WRITE,
                        PERF_COUNT_HW_CACHE_RESULT_MISS),
       .type = PERF_TYPE_HW_CACHE},
      {.name = "node-stores",
       .config =
           CACHE_CONFIG(PERF_COUNT_HW_CACHE_NODE, PERF_COUNT_HW_CACHE_OP_WRITE,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS),
       .type = PERF_TYPE_HW_CACHE},
  };

  __perf_event_list* ls = ALLOC(__perf_event_list);
  ls->n_events = sizeof(events) / sizeof(events[0]);
  ls->events = ALLOC_N(__perf_event, ls->n_events);
  memcpy(ls->events, events, sizeof(events));

  return ls;
}

static bool __is_empty_token(char* token) {
  // A token is empty if it is just containing delimiters or whitespaces.
  size_t ptr = 0;
  while (token[ptr] != '\0') {
    if (token[ptr] != ' ' && token[ptr] != ',') {
      return false;
    }
    ptr++;
  }

  return true;
}

static int __count_tokens(char** str, char delim) {
  size_t ptr = 0;
  // Escape leading whitespaces and redundant delimiters.
  while ((*str)[ptr] != '\0' && ((*str)[ptr] == ' ' || (*str)[ptr] == delim)) {
    ptr++;
  }

  *str = &((*str)[ptr]);  // Left trim.
  ptr = 0;                // Reset ptr.

  size_t tokens = 0;
  size_t prev_token = 0;
  while ((*str)[ptr] != '\0') {
    if ((*str)[ptr] == delim || (*str)[ptr + 1] == '\0') {
      // Create previous token.
      size_t tok_sz = ptr - prev_token;
      char* token = ALLOC_N(char, (tok_sz + 1));
      strncpy(token, &((*str)[prev_token]), tok_sz);
      token[tok_sz] = '\0';

      if (!__is_empty_token(token)) {
        tokens++;
      }

      prev_token = ptr;
      free(token);
    }
    ptr++;
  }
  return tokens;
}

#define RETURN_ERROR(log, ...)                                                 \
  do {                                                                         \
    char* buf = ALLOC_N(char, 512);                                            \
    snprintf(buf, 512, __VA_ARGS__);                                           \
    *log = buf;                                                                \
    return NULL;                                                               \
  } while (false)

static __perf_event_list* __parse_event_string(char* event_str,
                                               char** err_msg) {
  if (event_str == NULL || event_str[0] == '\0')
    RETURN_ERROR(err_msg, "Empty event string. Set PERF_EVENTS enviornment "
                          "variable with events to be monitored.");

  char* str = strdup(event_str);
  // Make a copy for freeing later since the next call to __count_tokens may
  // update the str pointer.
  char* str_copy CLEANUP = str;

  size_t n_events = __count_tokens(&str, ',');
  __perf_event* events = ALLOC_N(__perf_event, n_events);
  __perf_event_list* all_events CLEANUP = __get_perf_event_list();

  char* token;
  size_t event_idx = 0;
  while ((token = strsep(&str, ",")) != NULL) {
    if (__is_empty_token(token))
      continue;

    events[event_idx].name = strdup(token);

    if (!__update_event_config(&events[event_idx], all_events,
                               all_events->n_events)) {
      free(events);
      RETURN_ERROR(err_msg, "Unknown event - %s", events[event_idx].name);
    }
    event_idx++;
  }
  assert(event_idx == n_events);

  __perf_event_list* ls = ALLOC(__perf_event_list);
  ls->n_events = n_events;
  ls->events = events;
  return ls;
}

static __perf_event_group_list* __group_events(__perf_event_list* ls,
                                               char** err_msg) {
  size_t hw_events = 0, sw_events = 0, fixed_events = 0;
  for (size_t i = 0; i < ls->n_events; i++) {
    switch (ls->events[i].type) {
    case PERF_TYPE_HARDWARE: {
      if (ls->events[i].fixed) {
        fixed_events++;
      } else {
        hw_events++;
      }
      break;
    }
    case PERF_TYPE_HW_CACHE:
      hw_events++;
      break;
    case PERF_TYPE_RAW:
      hw_events++;
      break;
    case PERF_TYPE_SOFTWARE:
      sw_events++;
      break;
    default:
      RETURN_ERROR(err_msg, "Unknown event type - %d", ls->events[i].type);
    }
  }

  int group_cnt = 0;
  if (sw_events > 0) {
    // Lump all software events in to one group since software events are not
    // restricted on the number of available PMCs.
    group_cnt++;
  }
  // Fixed hardware events are scheduled in their own event groups.
  group_cnt += fixed_events;
  // Unconstrained (i.e: not explicitly pinned) programmable events are also
  // scheduled each in their own group to maximize PMC utilization.
  group_cnt += hw_events;

  __perf_event_group* groups = ALLOC_N(__perf_event_group, group_cnt);
  // Allocate first group for software events if any are present.
  if (sw_events > 0) {
    groups[0].n_events = 0;
    groups[0].events = ALLOC_N(__perf_event*, sw_events);
  }

  int ptr = sw_events > 0 ? 1 : 0;
  for (size_t i = 0; i < ls->n_events; i++) {
    if (ls->events[i].type == PERF_TYPE_SOFTWARE) {
      size_t event_ptr = groups[0].n_events;
      groups[0].events[event_ptr] = &(ls->events[i]);
      if (event_ptr == 0) {
        // Set the software event group leader as the first event in the group.
        groups[0].leader = groups[0].events[0];
      }
      groups[0].n_events++;
      continue;
    }

    // All other events in their own group.
    groups[ptr].n_events = 1;
    groups[ptr].events = ALLOC(__perf_event*);
    groups[ptr].events[0] = &(ls->events[i]);
    groups[ptr].leader = groups[ptr].events[0];
    ptr++;
  }
  assert(ptr == group_cnt);

  for (int i = 0; i < group_cnt; i++) {
    groups[i].event_ids = ALLOC_N(uint64_t, groups[i].n_events);
  }

  __perf_event_group_list* gls = ALLOC(__perf_event_group_list);
  gls->n_groups = group_cnt;
  gls->groups = groups;

  return gls;
}

static __perf_event_group_list* __init_event_groups(char* event_str,
                                                    char** err_msg) {
  __perf_event_list* ls = __parse_event_string(event_str, err_msg);
  if (ls == NULL)
    return NULL;

  /*
  fprintf(stdout, "[perf] Monitored events : ");
  for (size_t i = 0; i < ls->n_events; i++) {
    if (i < ls->n_events - 1) {
      fprintf(stdout, "%s, ", ls->events[i].name);
      continue;
    }
    fprintf(stdout, "%s\n\n", ls->events[i].name);
  }
  */

  __perf_event_group_list* gls = __group_events(ls, err_msg);
  // free_perf_event_list(ls);
  return gls;
}

static __perf_handle* __init_handle(const __perf_event_group_list* gls,
                                    int argc, char** argv) {
  size_t buf_sz = 0;
  for (size_t i = 0; i < argc; i++) {
    buf_sz += strlen(argv[i]);
    buf_sz++;  // Also store the C string terminator.
  }

  __perf_handle* h = ALLOC(__perf_handle);
  h->argv = ALLOC_N(char, buf_sz);

  size_t ptr = 0;
  for (size_t i = 0; i < argc; i++) {
    strncpy(&h->argv[ptr], argv[i], strlen(argv[i]));
    ptr += (strlen(argv[i]) + 1);
  }

  assert(ptr == buf_sz);
  h->argv_sz = ptr;

  h->gls = gls;
  return h;
}

static void __init_perf_event_attr(const __perf_event* event,
                                   struct perf_event_attr* attr) {
  memset(attr, 0, sizeof(struct perf_event_attr));
  attr->type = event->type;
  attr->size = sizeof(struct perf_event_attr);
  attr->config = event->config;
  attr->disabled = 1;
  attr->exclude_kernel = 1;
  attr->exclude_hv = 1;
  attr->pinned = event->pinned;

  // By default assume PMU multiplexing may happen.
  attr->read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
                      PERF_FORMAT_TOTAL_TIME_ENABLED |
                      PERF_FORMAT_TOTAL_TIME_RUNNING;
}

static __perf_handle* __register_events(__perf_handle* h, char** err_msg) {
  struct perf_event_attr attr;
  const __perf_event_group_list* gls = h->gls;
  for (int i = 0; i < gls->n_groups; i++) {
    __perf_event_group* g = &(gls->groups[i]);
    __perf_event* leader = g->leader;

    __init_perf_event_attr(leader, &attr);
    g->leader_fd = __perf_event_open(&attr, 0, -1, -1, 0);
    if (g->leader_fd == -1) {
      char buf[512];
      RETURN_ERROR(err_msg, "Error opening leader for %s - %s", leader->name,
                   strerror(errno));
    }
    ioctl(g->leader_fd, PERF_EVENT_IOC_ID, &(g->event_ids[0]));

    for (size_t j = 1; j < g->n_events; j++) {
      __perf_event* event = g->events[j];
      __init_perf_event_attr(event, &attr);

      int fd = __perf_event_open(&attr, 0, -1, g->leader_fd, 0);
      if (fd == -1) {
        char buf[512];
        RETURN_ERROR(err_msg, "Error opening event for %s with leader %s - %s",
                     event->name, leader->name, strerror(errno));
      }
      ioctl(fd, PERF_EVENT_IOC_ID, &(g->event_ids[j]));
    }
  }

  return h;
}

static __perf_handle* __init_perf(int argc, char** argv) {
  // Validate PMC availability assumptions.
  __pmc_info* info = __get_pmc_info();
  assert(info->fixed == 3);
  // fprintf(stdout, "[perf] Number of PMCs fixed|programmable = %d|%d\n",
  //        info->fixed, info->programmable);

  // Initialize perf event groups.
  char* err_msg;
  __perf_event_group_list* gls =
      __init_event_groups(getenv("PERF_EVENTS"), &err_msg);
  if (gls == NULL) {
    fprintf(stderr, "[perf] Initialization failure : %s\n", err_msg);
    free(err_msg);
    return NULL;
  }

  __perf_handle* h =
      __register_events(__init_handle(gls, argc, argv), &err_msg);
  if (h == NULL) {
    fprintf(stderr, "[perf] Event registration failure : %s\n", err_msg);
    free(err_msg);
    return NULL;
  }

  return h;
}

static void __start_perf(__perf_handle* h) {
  for (int i = 0; i < h->gls->n_groups; i++) {
    ioctl(h->gls->groups[i].leader_fd, PERF_EVENT_IOC_RESET,
          PERF_IOC_FLAG_GROUP);
    ioctl(h->gls->groups[i].leader_fd, PERF_EVENT_IOC_ENABLE,
          PERF_IOC_FLAG_GROUP);
  }
}

typedef struct __perf_counter {
  const char* name;
  uint64_t value;
  double scale;
} __perf_counter;

typedef struct __perf_counter_list {
  size_t n_counters;
  __perf_counter* counters;
} __perf_counter_list;

static __perf_counter_list* __read_counters(__perf_handle* h, FILE* fp) {
  const __perf_event_group_list* gls = h->gls;

  size_t n_counters = 0;
  for (int i = 0; i < gls->n_groups; i++) {
    n_counters += gls->groups[i].n_events;
  }
  __perf_counter* counters = ALLOC_N(__perf_counter, n_counters);

  char buf[4096];
  struct __read_format* rf = (struct __read_format*)buf;
  size_t counter_ptr = 0;
  for (int i = 0; i < gls->n_groups; i++) {
    memset(buf, 0, sizeof(buf));

    __perf_event_group* g = &(h->gls->groups[i]);
    read(g->leader_fd, buf, sizeof(buf));

    uint64_t time_enabled = rf->time_enabled;
    uint64_t time_running = rf->time_running;
    double scale = (double)time_running / time_enabled;

    for (size_t j = 0; j < g->n_events; j++) {
      for (size_t k = 0; k < rf->nr; k++) {
        if (rf->values[k].id == g->event_ids[j]) {
          __perf_counter counter;
          counter.name = g->events[j]->name;
          counter.value = rf->values[k].value;
          counter.scale = scale;
          counters[counter_ptr++] = counter;
        }
      }
    }
  }
  assert(counter_ptr == n_counters);

  __perf_counter_list* cls = ALLOC(__perf_counter_list);
  cls->n_counters = n_counters;
  cls->counters = counters;

  return cls;
}

static void __stop_perf(__perf_handle* h) {
  for (int i = 0; i < h->gls->n_groups; i++) {
    ioctl(h->gls->groups[i].leader_fd, PERF_EVENT_IOC_DISABLE,
          PERF_IOC_FLAG_GROUP);
  }

  __perf_counter_list* cls = __read_counters(h, stdout);

  char* outfile = getenv("PERF_OUTPUT");
  if (outfile == NULL) {
    outfile = ALLOC_N(char, 512);
    snprintf(outfile, 512, "%s_perf.csv", h->argv);
  }

  FILE* fp = fopen(outfile, "a+");

  // Write the csv header.
  //
  // Format : tag,<counter_1>,...,<counter_N>
  fprintf(fp, "tag");
  for (size_t i = 0; i < cls->n_counters; i++) {
    fprintf(fp, ",%s", cls->counters[i].name);
  }
  fprintf(fp, "\n");

  // Now write the data. Tag is the program name.
  fprintf(fp, "%s", h->argv);
  for (size_t i = 0; i < cls->n_counters; i++) {
    __perf_counter c = cls->counters[i];
    if (c.scale < 0) {
      fprintf(fp, ",%lu(%.2f)", (uint64_t)(c.value / c.scale), c.scale);
      continue;
    }
    fprintf(fp, ",%lu", c.value);
  }
  fprintf(fp, "\n");
  fflush(fp);
  fclose(fp);

  /*
  fprintf(stdout, "\n Performance counter stats for '");
  size_t ptr = 0;
  do {
    fprintf(stdout, "%s ", &h->argv[ptr]);
    ptr += (strlen(&h->argv[ptr]) + 1);
  } while (ptr < h->argv_sz - 1);
  fprintf(stdout, "':\n");

  for (size_t i = 0; i < cls->n_counters; i++) {
    if (cls->counters[i].scale < 0) {
      fprintf(stdout, "    %s  %lu(%lf)\n", cls->counters[i].name,
              cls->counters[i].value, cls->counters[i].scale);
      continue;
    }
    fprintf(stdout, "    %s  %lu\n", cls->counters[i].name,
            cls->counters[i].value);
  }

  fflush(stdout);
  */
}

#endif  // PERF_H_
