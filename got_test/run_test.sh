#!/bin/bash

for ((i=1; i<=10; i++)); do
    ./test_speed > data$i.txt 
done
