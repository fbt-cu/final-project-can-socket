#!/bin/sh

# arguments
filesdir=$1
searchstr=$2

# check that two arguments were input
if [ $# -ne 2 ] 
then
	echo "Error! Please provide two arguments: Directory path to search, text string to search"
	exit 1
elif [ ! -d $filesdir ]
then
	echo "Error! Path is not a directory"
	exit 1
fi

filecount=`ls -R1 $filesdir | grep -vc -e "^[\.]" -e"^$"  -e "^/"`
#echo $filecount
matchcount=`grep -R ${searchstr} ${filesdir} | grep -c ""`
#echo $matchcount

echo "The number of files are ${filecount} and the number of matching lines are ${matchcount}"

