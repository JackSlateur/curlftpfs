#!/bin/sh

echo "Running unittests:"

failed=0
for i in *_unittest; do
  echo -n "$i... "
  `./$i > /dev/null 2>&1`
  if [ $? == 0 ]; then
    echo "PASS"
  else
    echo "FAILED"
    failed=1;
  fi
done

exit $failed
