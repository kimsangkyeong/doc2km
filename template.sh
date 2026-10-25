#! /bin/sh
####################################################################################################
##
## File name : analy_web_ssl_access_info_adv.sh
## Description : Analyzing request count/response packet size using WEB SSL Access log.
## information : The file format for date extraction and the packet format for packet size extraction
##               are adjusted according to the form of the analysis file.. 
## 
##==================================================================================================
##  version   date             author      reason
##--------------------------------------------------------------------------------------------------
##  1.0       2020.07.29       k.s.k      First Created
##
####################################################################################################
# ======<<<< Signal common processing logic (Start) >>>>==============================================
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGINT ) captured" | tee -a ${logfnm}; exit 1;' SIGINT
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGQUIT) captured" | tee -a ${logfnm}; exit 1;' SIGQUIT
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGTERM) captured" | tee -a ${logfnm}; exit 1;' SIGTERM 
# ======<<<< Signal common processing logic (End) >>>>================================================

# ======<<<< Important Global Variable Registration Area Marking Comment (Start) >>>>=================
# Log file name variable for storing script execution information:used in Signal common processing logic
#logfnm="execute information log full path name : ex) /applog/infra/os/osstdchk.sh.log"
logdatefmt="%Y%m%d-%H:%M:%S"   # date/time format variable for logging info :used in Signal common logic

# total request count of all files
declare -A total_count
total_count=([all_req]=0 [sizeable_req]=0)
# total response packet size of all files
declare -A total_response_packet_size
total_response_packet_size=([GB]=0 [MB]=0 [KB]=0 [B]=0)
# unit size
declare -A unit_size
unit_size=([GB]=$(expr 1024 \* 1024 \* 1024) [MB]=$(expr 1024 \* 1024) [KB]=$(expr 1024 \* 1))
# total request count of single file
declare -A onefile_count
# total response packet size of single file
declare -A onefile_response_packet_size
# temporary variable
declare -A tmp_onefile_count
declare -A tmp_response_packet_size
# ======<<<< Important Global Variable Registration Area Marking Comment (End) >>>>===================
# ======<<<< Function Registration Area Marking Comment (Start) >>>>==================================
######################################################################################################
##  Function Name : get_unit_size_info
##  Description : Get string in unit size format.
##                And returns the converted string.
##  information : input packet size values by unit(GB, MB, KB, B)
##                output string format is ‘ 1 GB 1 MB 1 KB 2 Bytes’
######################################################################################################
get_unit_size_info()
{
  str_packet_size=""
  if [ "0" != "$1" ];
  then
    str_packet_size="$str_packet_size $1 GB"
  fi
  if [ "0" != "$2" ];
  then
    str_packet_size="$str_packet_size $2 MB"
  fi
  if [ "0" != "$3" ];
  then
    str_packet_size="$str_packet_size $3 KB"
  fi
  if [ "0" != "$4" ];
  then
    str_packet_size="$str_packet_size $4 Bytes"
  fi
  eval "$5=\"${str_packet_size}\""
}

######################################################################################################
##  Function Name : cumulate_data
##  Description : Cumulative calculation and output of extraction data.
##  information : input packet size value by unit(B), request counts
##                output none
######################################################################################################
cumulate_data()
{
  # assign argument values to local variables
  tmp_response_packet_size=([GB]=0 [MB]=0 [KB]=0 [B]=$2)
  tmp_onefile_count=([all_req]=$3 [sizeable_req]=$4)

  # size re-expression
  tmp_response_packet_size[GB]=$(expr "${tmp_response_packet_size[B]}" / "${unit_size[GB]}")
  tmp=$(expr "${tmp_response_packet_size[B]}" % "${unit_size[GB]}")
  tmp_response_packet_size[MB]=$(expr "${tmp}" / "${unit_size[MB]}")
  tmp=$(expr "${tmp}" % "${unit_size[MB]}")
  tmp_response_packet_size[KB]=$(expr "${tmp}" / "${unit_size[KB]}")
  tmp=$(expr "${tmp}" % "${unit_size[KB]}")
  tmp_response_packet_size[B]=${tmp}

  # total response packet size accumulation
  total_response_packet_size[GB]=$(expr "${total_response_packet_size[GB]}" + "${tmp_response_packet_size[GB]}")
  total_response_packet_size[MB]=$(expr "${total_response_packet_size[MB]}" + "${tmp_response_packet_size[MB]}")
  total_response_packet_size[KB]=$(expr "${total_response_packet_size[KB]}" + "${tmp_response_packet_size[KB]}")
  total_response_packet_size[B]=$(expr "${total_response_packet_size[B]}" + "${tmp_response_packet_size[B]}")

  # size re-expression
  if [ ${total_response_packet_size[B]} > ${unit_size[KB]} ];
  then
    total_response_packet_size[KB]=$(expr "${total_response_packet_size[KB]}" + "${total_response_packet_size[B]}" / "${unit_size[KB]}")
    total_response_packet_size[B]=$(expr "${total_response_packet_size[B]}" % "${unit_size[KB]}")
  fi
  if [ ${total_response_packet_size[KB]} > ${unit_size[KB]} ];
  then
    total_response_packet_size[MB]=$(expr "${total_response_packet_size[MB]}" + "${total_response_packet_size[KB]}" / "${unit_size[KB]}")
    total_response_packet_size[KB]=$(expr "${total_response_packet_size[KB]}" % "${unit_size[KB]}")
  fi
  if [ ${total_response_packet_size[MB]} > ${unit_size[KB]} ];
  then
    total_response_packet_size[GB]=$(expr "${total_response_packet_size[GB]}" + "${total_response_packet_size[MB]}" / "${unit_size[KB]}")
    total_response_packet_size[MB]=$(expr "${total_response_packet_size[MB]}" % "${unit_size[KB]}")
  fi

  # total request count accumulation
  total_count[all_req]=$(expr "${total_count[all_req]}" + "${tmp_onefile_count[all_req]}")
  total_count[sizeable_req]=$(expr "${total_count[sizeable_req]}" + "${tmp_onefile_count[sizeable_req]}")

  #get string in unit size format of one file response packet size
  get_unit_size_info ${tmp_response_packet_size[GB]} ${tmp_response_packet_size[MB]} ${tmp_response_packet_size[KB]} ${tmp_response_packet_size[B]} str_response_packet_size

  #get string in unit size format of accumulated total response packet size
  get_unit_size_info ${total_response_packet_size[GB]} ${total_response_packet_size[MB]} ${total_response_packet_size[KB]} ${total_response_packet_size[B]} str_total_response_packet_size

  echo "req_date : $1 , response_packet_size : $2 Bytes [${str_response_packet_size}] >> total_response_packet_size : [ ${str_total_response_packet_size} ] , sizeable_packet_request_count : [ ${total_count[sizeable_req]} ], all_packet_request_count : [ ${total_count[all_req]} ] "
}

######################################################################################################
##  Function Name : analy_summary_packet
##  Description : Extract the packet size and number of requests from one file.
##  information : input filename
##                output none
######################################################################################################
analy_summary_packet()
{
  echo "filename : $1 "
  # date
  var_dt=$(basename $1 | cut -d'.' -f3)

  # initailize
  onefile_count=([all_req]=0 [sizeable_req]=0)
  onefile_response_packet_size=([GB]=0 [MB]=0 [KB]=0 [B]=0)

  for ipacket in $(cat $1 | cut -d'"' -f3 | tr ' ' '!' | cut -d'!' -f3 )
  do
#    echo "$ipacket"
    if [ "$ipacket" != "-" ]
    then
      onefile_response_packet_size[B]=$(expr "${onefile_response_packet_size[B]}" + "$ipacket")
      onefile_count[sizeable_req]=$(expr "${onefile_count[sizeable_req]}" + 1)
    fi
    onefile_count[all_req]=$(expr "${onefile_count[all_req]}" + 1)
  done

  # cumulate data
  cumulate_data $var_dt ${onefile_response_packet_size[B]} ${onefile_count[all_req]} ${onefile_count[sizeable_req]}
}

######################################################################################################
##  Function Name : is_analysis_file
##  Description : To check if the file is a plintext file.
##  information : input filename
##                output -1 : zipfile,  1 : plaintext
######################################################################################################
is_analysis_file()
{
  # gzip file skip
  gzip -t $1 > /dev/null 2>&1
  if [ $? -eq 0 ];
  then
    echo "........ $1 is not plaintext file. (gzip file) - skip ......"
    return -1
  fi    
  return 1
}
# ======<<<< Function Registration Area Marking Comment (End) >>>>===================================
# ======<<<< Main Logic Coding Area Marking Comment (Start) >>>=======================================
for ix in $(ls `pwd`/ssl_access.log.*)
do
  #file only
  if [ -f $ix ]
  then
    # gzip file skip
    gzip -t $ix > /dev/null 2>&1
    if [ $? -eq 0 ];
    then
      echo "........ $ix is gzip file - skip ......"
    else
      # analyze file
      analy_summary_packet $ix 
    fi
  fi
done
# ======<<<< Main Logic Coding Area Marking Comment (End) >>>=========================================