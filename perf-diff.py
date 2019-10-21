#!/usr/bin/env python3
'''
 perf-diff -- Capture micro-achitectural event diffs.
 <http://github.com/chamibuddhika/perf-diff>
 
 Copyright (c) 2019 Buddhika Chamith
 
 Permission is hereby granted, free of charge, to any person obtaining a
 copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 IN THE SOFTWARE.
 
 Date : 10/20/2019
'''

import argparse
import csv
import sys
import matplotlib.pyplot as plt

from collections import defaultdict
from tabulate import tabulate

class Diff(object):
    def __init__(self, key, before, after):
        self.key = key
        self.before = int(before) 
        self.after = int(after)
        self.diff_val = self.after - self.before 
        self.diff = round((self.diff_val / self.before) * 100, 2)

    def asList(self):
        return [self.key, self.before, self.after, self.diff_val, self.diff]

class PerfDiff(object):
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Diff two perf stat csv files')
        parser.add_argument('-s', '--sort', action='store_false',\
                help='sort output by diffs (in increasing order)')
        parser.add_argument('before')
        parser.add_argument('after')

        self.diff(parser)


    def _read_csv(self, f):
        with open(f) as csvfile:
            reader = csv.DictReader(csvfile, delimiter=',')
            # Currently we only capture one result.
            for row in reader:
                return row;

    def diff(self, parser):
        args = parser.parse_args(sys.argv[1:])
 
        before_data = self._read_csv(args.before)
        after_data = self._read_csv(args.after)

        data_table = []
        counters = []
        for k, v in before_data.items():
            if k != "tag" and after_data[k]:
                counters.append(k)
                data_table.append(Diff(k, v, after_data[k]).asList()[1:]) 

        plt.table(cellText=data_table, colLabels=['Before', 'After','Diff', 'Diff(%)'], \
                rowLabels=counters, loc='center')
        # Removing ticks and spines in the table figure.
        plt.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=False)
        plt.tick_params(axis='y', which='both', right=False, left=False, labelleft=False)
        for pos in ['right','top','bottom','left']:
            plt.gca().spines[pos].set_visible(False)

        plt.savefig('result_table.pdf', bbox_inches='tight', pad_inches=0.05)

if __name__ == "__main__":
    PerfDiff()
