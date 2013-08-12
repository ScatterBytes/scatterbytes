#!/bin/sh

tmp_file=/tmp/pymetrics_filelist.txt
find . -name "*.py" > $tmp_file
pymetrics --nosql --nocsv -f $tmp_file
