#!/bin/bash
cd /home/con/workspace/PtProxy || exit;
conf='/home/con/workspace/PtProxy/config.yaml';
/usr/bin/python3.10 /home/con/workspace/PtProxy/main.py $conf;
if [ $? == 0 ]; then
  if [ -f "convert_config.py" ]; then
    /usr/bin/python3.10 /home/con/workspace/PtProxy/convert_config.py $conf;
  fi
fi
