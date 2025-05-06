# Flow Log Parsing Program

## Assumptions
1. Program only supports flow logs of version 2.
2. Malformed rows are meant to be insufficient and skipped.
3. A destination port 0 in the lookup table is NOT a catch-all for all records with matching protocol.

## Edge Cases Tested:
1. Missing or malformed files.
2. Empty rows or rows with insufficient data.
3. Large file sizes and performance optimization.

## How to Run
1. Place the flow log file and lookup table file in the same directory as the program.
2. Run the program with the following command:
python3 match.py <lookup_table.csv> <flow_logs.txt>
3. The output will be saved to `output.txt`.
