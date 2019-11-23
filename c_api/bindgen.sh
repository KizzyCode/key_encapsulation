#!/bin/sh

bindgen --use-core \
  --whitelist-type slice_t --no-copy slice_t \
  --whitelist-type write_t --no-copy write_t \
  --whitelist-type init \
  --whitelist-type id \
  --whitelist-type configs \
  --whitelist-type auth_info_protect \
  --whitelist-type auth_info_recover \
  --whitelist-type set_context \
  --whitelist-type protect \
  --whitelist-type recover \
  kync.h