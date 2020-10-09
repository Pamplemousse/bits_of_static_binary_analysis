#!/usr/bin/env bash

function markdownify() {
  local SOURCE_FILE=$1

  MARKDOWN_FILE="$(echo "$SOURCE_FILE" | cut -d'.' -f 1).md"

  cat << __EOF__ > "$MARKDOWN_FILE"
\`\`\`python
#
# "$MARKDOWN_FILE"
#

$(cat "$SOURCE_FILE")
\`\`\`
__EOF__
}

function pdfify() {
  local FILE="$1"

  if ! docker images | grep "pamplemousse/nodejs" >/dev/null; then
    docker pull pamplemousse/nodejs
  fi

  # Using https://www.npmjs.com/package/markdown-pdf.
  docker run --rm \
    -v "$(pwd)":/app \
    -w /app \
    pamplemousse/nodejs \
    markdown-pdf "$FILE"
}

function _help() {
  echo "Get the examples in a printable format."
  echo "Usage: ./tasks/examples_to_pdf.sh [OPTIONS]"
  echo -e "\t\t-h\t Display help."
  echo -e "\t\t-m\t Merge all PDFs generated from examples in a single PDF."
}


OPTSTRING=":hm"
while getopts "${OPTSTRING}" ARG; do
  case "${ARG}" in
    h)
      _help
      exit
      ;;
    m)
      MERGE_PDFS=1
      ;;
    :)
      echo "$0: Must supply an argument to -$OPTARG." >&2
      exit 1
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 2
      ;;
  esac
done

if [ ! "$0" == "./tasks/examples_to_pdf.sh" ]; then
  echo "This task should be ran from the root of the repository!" >&2
  exit
fi

cd examples || exit

for EXAMPLE in *.py; do
  markdownify "$EXAMPLE"
  pdfify "$MARKDOWN_FILE"
done

if [ -n "${MERGE_PDFS+x}" ]; then
  if ! command -v gs &> /dev/null; then
    docker pull pamplemousse/latex >/dev/null
    function gs() {
      docker run --rm \
        -v "$(pwd)":/app -w /app \
        pamplemousse/latex \
        gs "$@"
    }
  fi

  gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=all_examples.pdf ./*.pdf
  find . -type f -name '*.pdf' -not -name 'all_examples.pdf' -delete
fi
mv ./*.pdf ..
rm ./*.md
