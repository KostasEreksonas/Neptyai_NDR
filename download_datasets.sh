#!/bin/sh

if ! [ -d 'datasets.uwf.edu/' ]; then
	wget -np -r https://datasets.uwf.edu/data/UWF-ZeekData22/
	wget -np -r https://datasets.uwf.edu/data/UWF-ZeekData24/
	wget -np -r https://datasets.uwf.edu/data/UWF-ZeekDataFall22/
	wget -np -r https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/
	wget -np -r https://datasets.uwf.edu/data/UWF-ZeekDataSum25-1/
	wget -np -r https://datasets.uwf.edu/data/UWF-ZeekDataSum25-2/
else
	printf "Datasets already downloaded\n"
fi
