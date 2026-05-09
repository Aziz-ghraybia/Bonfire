#!/bin/bash

find . -type f | while read file
do
    sha=$(sha256sum "$file" | awk '{print $1}')
    echo "$file : $sha"
done
