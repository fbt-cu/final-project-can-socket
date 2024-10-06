#!/bin/bash

# arguments
writefile=$1
writestr=$2

# check that two arguments were input
if [ $# -ne 2 ]
then
        echo "Error! Please provide two arguments: Path and file name to create, text string to write to file"
        exit 1
fi

# build array to manage paths, replace "/" with "/ " to allow easier concatenation
array=(${writefile///// })

#echo "Original array: ${array[@]}"

# remove last element (last element is the file name)
unset 'array[-1]'
#echo "Array without the file name: ${array[@]}"

# if the first element of the array is just / append that to the first element
if [ ${array[0]} = "/" ] 
then
	array[1]="/${array[1]}"
	unset 'array[0]'
	#echo "Array after changes: ${array[@]}"
fi	

# create all directories needed
for path_var in ${array[@]}
do
	# append path
        temp_path="$temp_path$path_var"
        #echo "This is the path to test: $temp_path"
	if [ ! -d $temp_path ]
	then
		#echo "Path does not exist, create folder"
		mkdir $temp_path
	#else
		#echo "Path exists, no need to create folder"
	fi
	#echo $path_var
done


echo $writestr > $writefile
#echo "File $writefile created (or replaced) with content $writestr"
