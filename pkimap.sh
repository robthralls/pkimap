#!/bin/sh
# pkimap - certificate authority discovery
#
# Copyright (c) Robert Thralls
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


log () {
  printf "%s\n" "${*}" >&2
}

main () {
  [ "${1}" ] || exit 1
  count=0
  timestamp="$(date '+%Y.%m.%d-%H%M%S')"
  work_dir="$(mktemp -d "/tmp/pkimap.${timestamp}.XXXXXXXX")"
  parse_cert "${1}" > "${work_dir}/root.pem" || exit 1
  cd "${work_dir}"
  while true; do
    start_p7c="$(ls | egrep '.p7c$')" 
    start_pem="$(ls | egrep '.pem$')" 

    # Search certificates for their issued certificate repositories.
    p7c_list="$(mktemp "${work_dir}"/p7c_list.XXXXXXXX)"
    for i in *.pem; do
      find_repo "${i}"
    done | sort -u > "${p7c_list}"

    # Download any repositories we don't have yet.
    while IFS= read -r line; do
      p7c_file="${work_dir}/$(printf "%s\n" "${line}" | sha 1).p7c"
      if [ ! -f "${p7c_file}" ]; then
        curl -s --connect-timeout 5 --max-time 10 "${line}" -o "${p7c_file}"
        if grep -q href "${p7c_file}"; then
          line="$(grep -Eoi '<a [^>]+>' "${p7c_file}" | grep -Eo 'href="[^\"]+"' | grep -Eo '(http|https)://.*[^/"]+')"
          curl -s --connect-timeout 5 --max-time 10 "${line}" -o "${p7c_file}"
        fi
      fi
    done < "${p7c_list}"
    rm "${p7c_list}"

    # Extract certificates from repositories.
    for i in *.p7c; do
      printf "%s\n" "${start_p7c}" | grep -qFx "${i}" && continue
      p7c_temp="$(mktemp "${work_dir}"/p7c_temp.XXXXXXXX)"
      parse_repo "${i}" > "${p7c_temp}" \
        || printf "%s\n" "${i}" >> "${work_dir}/pkcs7_fail"
      split_repo "${p7c_temp}"
      rm -f "${p7c_temp}"
    done
    [ "${start_pem}" = "$(ls *.pem)" ] && log "Discovery complete." && break
    count="$((count + 1))"
    [ "${count}" = "10" ] && log "Too many rounds." && exit 1
  done

  if [ -f "${work_dir}/pkcs7_fail" ]; then
    log "Failed to parse these certificate repositories:"
    sort -u "${work_dir}/pkcs7_fail" >&2
  fi

  log "Generating CSV... "
  csv_temp="$(mktemp "${work_dir}"/csv.XXXXXXXX)"
  for i in *.pem; do
    # this could be streamlined a bit...
    printf "%s;"                                             \
      "${i}"                                                 \
      "$(openssl x509 -noout -issuer_hash -in "${i}")"       \
      "$(grep -A 1 'X509v3 Authority Key Identifier:' "${i}" \
          | grep -v 'X509v3'                                 \
          | sed 's/ *keyid://')"                             \
      "$(openssl x509 -noout -issuer -in "${i}"              \
          | sed -e 's/issuer= *//')"                         \
      "$(openssl x509 -noout -subject_hash -in "${i}")"      \
      "$(grep -A 1 'X509v3 Subject Key Identifier:' "${i}"   \
          | grep -v 'X509v3'                                 \
          | sed 's/ *//')"                                   \
      "$(openssl x509 -noout -subject -in "${i}"             \
          | sed -e 's/subject= *//')"                        \
      "$(openssl x509 -noout -enddate -in "${i}"             \
          | sed -e 's/.*=//')"                               \
      ""                                                     \
      "$(grep 'URI:http' "${i}"                              \
          | egrep '.crl$'                                    \
          | sed -e 's/.*URI://'                              \
          | tr '\n' ';')"                                    \
      >> "${csv_temp}"
    printf "\n" >> "${csv_temp}"
  done
  csv_final="/tmp/pkimap.${timestamp}.csv"
  printf "%s%s\n"                                                     \
    "File Name;Iss_Hash;Authority Key Identifier;Issuer Name;"        \
    "Sub_Hash;Subject Key Identifier;Subject;Expires;;Authority CRLs" \
    > "${csv_final}"
  grep '^root.pem' "${csv_temp}" >> "${csv_final}"
  sed -e '/^root[.]pem/d' "${csv_temp}" > "${csv_temp}.sed"
  mv "${csv_temp}.sed" "${csv_temp}"

  csv_recurse 
  rm "${work_dir}"/csv_lines.*

  printf "\n\n" >> "${csv_final}"
  cat "${csv_temp}" >> "${csv_final}"
  rm -f "${csv_temp}"
  printf "%s\n" "${csv_final}"
}

sha () {
  local alg="${1}"
  shift
  case "$(uname -s)" in
    Linux )
      case "${alg}" in
          1 ) sha1sum "${@}" | awk '{ print $1 }';;
        512 ) sha512sum "${@}" | awk '{ print $1 }';;
      esac
      ;;
    OpenBSD | FreeBSD )
      case "${alg}" in
          1 ) sha1 "${@}" | sed -e 's/.*= //';;
        512 ) sha512 "${@}" | sed -e 's/.*= //';;
      esac
      ;;
    Darwin )
      case "${alg}" in
          1 ) shasum -a 1 "${@}" | awk '{ print $1 }';;
        512 ) shasum -a 512 "${@}" | awk '{ print $1 }';;
      esac
      ;;
    * )
      case "${alg}" in
          1 ) openssl sha1 "${@}" | sed -e 's/.*= //';;
        512 ) openssl sha512 "${@}" | sed -e 's/.*= //';;
      esac
    ;;
  esac
}

get_format () {
  local out=
  if printf "%s" "$(file -b "${1}")" | egrep -q "^ASCII text" \
    || [ "$(file -b "${1}")" = "PEM certificate" ]; then
    if grep -qI '\-----BEGIN' "${1}"; then
      out="pem"
    else
      out="base64"
    fi
  else
    out="der"
  fi
  printf "%s\n" "${out}"
}

parse_cert () {
  local form="$(get_format "${1}")"
  case "${form}" in
    pem | der )
      openssl x509 -text -in "${1}" -inform ${form} -outform pem
      ;;
    base64 )
      base64 -d "${1}" | openssl x509 -text -inform der -outform pem
      ;;
    * )
      log "failed to sanitize certificate: ${1}"
      ;;
  esac
}

find_repo () {
  grep 'CA Repository - URI:http' "${1}" | sed -e 's/.*URI://'
}

parse_repo () {
  local form="$(get_format "${1}")"
  case "${form}" in
    pem | der )
      openssl pkcs7 -in "${1}" -inform ${form} -print_certs
      ;;
    base64 )
      base64 -d "${1}" | openssl pkcs7 -inform der -print_certs
      ;;
    * )
      log "failed to read repository: ${1}"
      exit 1
      ;;
  esac
}

split_repo () {
  while IFS='' read -r line; do
    line="$(printf "%s\n" "${line}" | sed -e 's/#.*//')"
    [ -z "${line}" ] && continue
    if [ "${line}" = "-----BEGIN CERTIFICATE-----" ]; then
      is_cert="true"
      x509_temp="$(mktemp "${work_dir}"/x509_temp.XXXXXXXX)"
    fi
    [ "${is_cert}" = "true" ] && printf "%s\n" "${line}" >> "${x509_temp}"
    if [ "${line}" = "-----END CERTIFICATE-----" ]; then
      is_cert="false"
      x509_text="$(mktemp "${work_dir}"/x509_text.XXXXXXXX)"
      openssl x509 -text -in "${x509_temp}" > "${x509_text}"
      rm "${x509_temp}"
      shash="$(openssl x509 -noout -subject_hash -in "${x509_text}")"
      sha512="$(sha 512 "${x509_text}")"
      if sha 512 ${shash}.*.pem 2> /dev/null | grep -q "${sha512}"; then
        rm -f "${x509_text}"
      else
        count="$(ls "${shash}".* 2> /dev/null | wc -l | awk '{ print $1 }')"
        moveto="${work_dir}/${shash}.${count}.pem"
        mv "${x509_text}" "${moveto}"
      fi
    fi
  done < "${1}"
}

csv_recurse () {
  ski="$(tail -n 1 "${csv_final}" | awk -F ';' '{ print $6 }')"
  lines="$(mktemp "${work_dir}"/csv_lines.XXXXXXXX)"
  egrep "^[^;]*;[^;]*;${ski}" "${csv_temp}" \
    | sort -t ';' -k4,5 \
    | sort -t ';' -k7,8 \
    > "${lines}"
  while IFS='' read -r line; do
    search="$(printf "%s" "${line}" | sed -e 's/\//\\\//g')"
    sed -e "/^${search}$/d" "${csv_temp}" > "${csv_temp}.sed"
    mv "${csv_temp}.sed" "${csv_temp}"
    sed -e "/^[^;]*;[^;]*;[^;]*;[^;]*;[^;]*;${ski}/d" "${csv_temp}" \
      > "${csv_temp}.sed"
    mv "${csv_temp}.sed" "${csv_temp}"
  done < "${lines}"
  while IFS='' read -r line; do
    printf "%s\n" "${line}" >> "${csv_final}"
    csv_recurse
  done < "${lines}"
}

main "${@}"

