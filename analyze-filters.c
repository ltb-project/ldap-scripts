/*
  Program: Analyze filters in OpenLDAP logs <analyze-filters.c>

  Source code home: https://github.com/ltb-project/ldap-scripts/analyze-filters.c

  Author: LDAP Tool Box project
  Author: David Coutadeur <david.coutadeur@gmail.com>

  Current Version: 1

  Purpose:
   Display the number of occurrences for each type of filter in OpenLDAP logs
   Mainly used for index tuning

  License:

   Redistribution and use in source and binary forms, with or without
   modification, are permitted only as authorized by the OpenLDAP
   Public License.

   A copy of this license is available in the file LICENSE in the
   top-level directory of the distribution or, alternatively, at
   <http://www.OpenLDAP.org/license.html>.

  Installation:
    1. Enable a minimum of 'loglevel 256' in OpenLDAP configuration
    2. Copy the perl script to a suitable location.
    3. Refer to the usage section for options and examples.

  Usage:
    gcc analyze-filters.c -o analyze-filters
    ./analyze-filters slapd.log
*/


#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>

#define LINE_MAX_SIZE 16384
#define FILTER_MAX_SIZE 1024
#define MAX_FILTERS 256
#define ATTR_MAX_SIZE 128
#define VAL_MAX_SIZE 1024

typedef struct sfilter sfilter;
struct sfilter
{
    char filter[FILTER_MAX_SIZE];
    int occurrence;
};

int min_length(char *string1, char *string2)
{
    int i = strlen(string1);
    int j = strlen(string2);

    if(i <= j)
    {
        return i;
    }
    else
    {
        return j;
    }
}

void insert_filter(sfilter *full_filter, char *formatted_filter)
{
    int i = 0;

    // search for an existing filter
    while( full_filter[i].occurrence != 0 )
    {
        if(strncmp(full_filter[i].filter,
                   formatted_filter,
                   min_length(full_filter[i].filter, formatted_filter) ) == 0)
        {
            // found identical filter
            // just increment occurrence
            full_filter[i].occurrence++;
            return;
        }
        
        i++;
    }

    // else, existing filter not found, just add it to the end
    strncpy(full_filter[i].filter,formatted_filter,strlen(formatted_filter));
    full_filter[i].filter[strlen(formatted_filter)] = '\0';
    full_filter[i].occurrence++;

    full_filter[(i+1)].occurrence = 0;
}

// replace "src" leading characters by "dst"
void leadingpad(char *string, char src, char dst)
{
    int i = 0;
    while( string[i] == src )
    {
        string[i] = dst;
        i++;
    }
}

void display_filters(sfilter *full_filter)
{
    int i = 0;
    char occurrence[13];

    printf("| Occurrences | Full filters                                                   |\n");
    printf("+-------------+----------------------------------------------------------------+\n");
    while( full_filter[i].occurrence != 0 )
    {
        sprintf(occurrence, "%12d", full_filter[i].occurrence);
        leadingpad(occurrence, '0',' ');
        printf("|%s | %62s |\n" , occurrence, full_filter[i].filter);
        i++;
    }

}

void swap_filters(sfilter *full_filter, int i, int j)
{
    int occurrence;
    char filter[FILTER_MAX_SIZE];

    // copy i filter to temporary variables
    occurrence = full_filter[i].occurrence;
    strncpy(filter, full_filter[i].filter, strlen(full_filter[i].filter));
    filter[strlen(full_filter[i].filter)] = '\0';

    // replace i filter with j values
    full_filter[i].occurrence = full_filter[j].occurrence;
    strncpy(full_filter[i].filter, full_filter[j].filter, strlen(full_filter[j].filter));
    full_filter[i].filter[strlen(full_filter[j].filter)] = '\0';

    // replace j filter with i values
    full_filter[j].occurrence = occurrence;
    strncpy(full_filter[j].filter, filter, strlen(filter));
    full_filter[j].filter[strlen(filter)] = '\0';
}

void sort_filters(sfilter *full_filter)
{
    int i, j;
    int max;

    i = 0;
    while( full_filter[i].occurrence != 0 )
    {
        max = i;;
        j = i + 1;
        while( full_filter[j].occurrence != 0 )
        {
            if(full_filter[j].occurrence > full_filter[max].occurrence)
            {
                max = j;
            }
            j++;
        }
        if(max != i)
        {
            swap_filters(full_filter, max, i);
        }
        i++;
    }

}

// Replace all non * word by <value>
void format_value(char *formatted_value, char *value)
{
    char pattern[] = "<value>";
    char delim = '*';

    char *cursor;
    char *start = value;

    for( cursor = value; cursor[0] != '\0' ; cursor++ )
    {
       if( cursor[0] == delim )
       {
          if( (cursor - start) > 0 )
          {
              strcat(formatted_value, pattern );
          }
          strncat(formatted_value, &delim, 1 );
          start = cursor;
          start++;
       }
    }
    if( (cursor - start) > 0 )
    {
        strcat(formatted_value, pattern );
    }
}

void compute_full_filter(sfilter *full_filter, char *current_filter, regex_t *pregf)
{

    // regex stuff
    int rc;
    size_t nmatch = 3; // 3 matches: the total regex + 2 capture groups
    regmatch_t pmatch[3];
    char *cursor;

    // temporary string to store attribute
    char attribute[ATTR_MAX_SIZE];
    char value[VAL_MAX_SIZE];
    char formatted_value[VAL_MAX_SIZE];
    char formatted_filter[FILTER_MAX_SIZE] = "";


    cursor = current_filter;
    while ( ( rc = regexec(pregf, cursor, nmatch, pmatch, 0)) == 0 )
    {
        if( pmatch[1].rm_so != ( (size_t) - 1 ) && pmatch[2].rm_so != ( (size_t) - 1 ) )
        {
            formatted_value[0] = '\0'; // empty string

            // get attribute
            strncpy (attribute, &cursor[(pmatch[1].rm_so)], ( pmatch[1].rm_eo - pmatch[1].rm_so ) );
            attribute[(pmatch[1].rm_eo - pmatch[1].rm_so)] = '\0';

            // get value
            strncpy (value, &cursor[(pmatch[2].rm_so)], ( pmatch[2].rm_eo - pmatch[2].rm_so ) );
            value[(pmatch[2].rm_eo - pmatch[2].rm_so)] = '\0';
            format_value(formatted_value, value);

            // combine format_filter parts
            strncat(formatted_filter, cursor, pmatch[1].rm_so);
            strcat(formatted_filter, attribute);
            strcat(formatted_filter, "=");
            strcat(formatted_filter, formatted_value);
            strcat(formatted_filter, ")");

            cursor += pmatch[2].rm_eo;
            cursor++;
        }
    }

    strcat(formatted_filter, cursor);
    insert_filter(full_filter, formatted_filter);
    
}

int main( int argc, char **argv )
{
    // file stuff
    FILE * fp;
    char line[LINE_MAX_SIZE];
    size_t len = 0;
    ssize_t read;

    // regex stuff
    regex_t preg, pregf;
    char *pattern = "filter=\"([^\"]+)\"";
    char *patternf = "\\(([^=\\(]+)=([^\\)]+)\\)";
    int rc;
    size_t nmatch = 2; // 2 matches: the total regex + the first capture group
    regmatch_t pmatch[2];

    // temporary string to store current filter
    char current_filter[FILTER_MAX_SIZE];

    // structures storing the filters
    sfilter full_filter[MAX_FILTERS] = { { .filter = "", .occurrence = 0 } };
    sfilter comp_filter[MAX_FILTERS] = { { .filter = "", .occurrence = 0 } };


    if(argc != 2)
    {
        printf("Missing file name\n");
        exit(1);
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL)
        exit(1);

    if ((rc = regcomp(&preg, pattern, REG_EXTENDED)) != 0) {
       printf("regcomp() failed, returning nonzero (%d)\n", rc);
       exit(1);
    }

    if ((rc = regcomp(&pregf, patternf, REG_EXTENDED)) != 0) {
       printf("regcomp() failed, returning nonzero (%d)\n", rc);
       exit(2);
    }



    // parse file
    while (fgets(line,LINE_MAX_SIZE, fp))
    {
        // only get filter="..." part
        if ((rc = regexec(&preg, line, nmatch, pmatch, 0)) == 0)
        {
            if( pmatch[1].rm_so != ( (size_t) - 1 ) )
            {
                strncpy (current_filter, &line[(pmatch[1].rm_so)], ( pmatch[1].rm_eo - pmatch[1].rm_so ) );
                current_filter[(pmatch[1].rm_eo - pmatch[1].rm_so)] = '\0';
                compute_full_filter(full_filter, current_filter, &pregf);
            }
        }
    }

    regfree(&preg);
    regfree(&pregf);
    fclose(fp);

    sort_filters(full_filter);
    display_filters(full_filter);

    exit(0);
}
