#!/bin/bash

# Check if the user provided a search query
if [ -z "$1" ]; then
    echo "Usage: $0 <search_query>"
    exit 1
fi

# Join the command-line arguments to form the search query
search_query="$*"

# Replace spaces with plus signs for the query
search_query=$(echo "$search_query" | sed 's/ /+/g')

# Perform the web search using Google
search_url="https://www.google.com/search?q=$search_query"
echo "Searching for: $search_query"
echo "Opening: $search_url"

# Open the default web browser with the search results
