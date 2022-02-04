#!/usr/bin/env bash
set -eu

# sign_binary [binary-path] [signing-identity]
#
# signs a single binary with cosign
#
sign_binary() {
  exe_path=$1
  identity=$2

  if [ -x "$exe_path" ] && file -b "$exe_path" | grep -q "Mach-O"
  then
      echo "signing $exe_path ..."
  else
      echo "skip signing $exe_path ..."
      return 0
  fi

  codesign \
    -s "$identity" \
    -f \
    --verbose=4 \
    --timestamp \
    --options runtime \
      $exe_path

  if [ $? -ne 0 ]; then
      exit_with_error "signing failed"
  fi

  codesign --verify "$exe_path"  --verbose=4

  if [ $? -ne 0 ]; then
      exit_with_error "signing verification failed"
  fi
}

# sign_binaries_in_archive [archive-abs-path] [signing-identity]
#
# signs all binaries within an archive (there must be at least one)
#
sign_binaries_in_archive() {
  archive_abs_path=$1
  identity=$2
  
  scratch_path=$(mktemp -d)
  trap "rm -rf -- $scratch_path" EXIT

  title "getting contents from the release archive: $archive_abs_path"
  tar -C "$scratch_path" -xvf "$archive_abs_path"
  
  # invalidate the current archive, we only want an asset with signed binaries from this point forward
  rm "$archive_abs_path"
  
  title "signing binaries found in the release archive"
  
  discovered_binaries=0
  tmp_pipe=$(mktemp -ut pipe.XXX)
  mkfifo "$tmp_pipe"
  
  find "$scratch_path" -perm +111 -type f > "$tmp_pipe" &
  
  while IFS= read -r binary; do
    sign_binary "$binary" "$identity"
    ((discovered_binaries++))
  done < "$tmp_pipe"
  
  rm "$tmp_pipe"
  
  if [ "$discovered_binaries" = "0" ]; then
      exit_with_error "found no binaries to sign"
  fi
  
  title "recreating the release archive: $archive_abs_path"
  (cd "$scratch_path" && tar -czvf "$archive_abs_path" .)
}

