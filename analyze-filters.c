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
    2. Copy the program to a suitable location.
    3. Refer to the usage section for options and examples.

  Usage:
    gcc -Wall -o analyze-filters analyze-filters.c -lpcre2-8
    ./analyze-filters slapd.log
*/

#define PCRE2_CODE_UNIT_WIDTH 8
#define LINE_MAX_SIZE 65536
#define FILTER_MAX_SIZE 16384
#define FILTER_COMP_MAX_SIZE 256
#define MAX_FILTERS 2048
#define ATTR_MAX_SIZE 256
#define VAL_MAX_SIZE 1024


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre2.h>

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

void compute_filter(sfilter *full_filter, sfilter *comp_filter, char *current_filter, pcre2_code *ref)
{

    char *cursor;

    /* for pcre2_compile */
    PCRE2_SIZE erroffset;
    int errcode;
    PCRE2_UCHAR8 buffer[128];

    /* for pcre2_match */
    int rc;
    PCRE2_SIZE* ovector;
    uint32_t options = 0;
    pcre2_match_data *match_data;
    uint32_t ovecsize = 128;
    PCRE2_SPTR attr_start, val_start;
    PCRE2_SIZE attr_len, val_len;
    PCRE2_SIZE attr_pos = 1; // first match is at position 1
    PCRE2_SIZE val_pos = 2; // second match is at position 2

    // temporary string to store attribute
    char attribute[ATTR_MAX_SIZE];
    char value[VAL_MAX_SIZE];
    char formatted_value[VAL_MAX_SIZE];
    char formatted_filter[FILTER_MAX_SIZE] = "";
    char formatted_comp_filter[FILTER_COMP_MAX_SIZE];


    cursor = current_filter;
    match_data = pcre2_match_data_create(ovecsize, NULL);
    while ( (rc = pcre2_match(ref, cursor, strlen(cursor), 0, options, match_data, NULL)) >= 0 )
    {

        if(rc == 0) {
            // error
            fprintf(stderr,"offset vector too small: %d\n",rc);
        }
        else if(rc == 3) // 3 = one regex matching (1) + two matching group (2)
        {
            formatted_value[0] = '\0'; // empty string
            formatted_comp_filter[0] = '\0'; // reinitialize component filter

            ovector = pcre2_get_ovector_pointer(match_data);
            attr_start = cursor + ovector[2*attr_pos];
            attr_len = ovector[2*attr_pos+1] - ovector[2*attr_pos];
            val_start = cursor + ovector[2*val_pos];
            val_len = ovector[2*val_pos+1] - ovector[2*val_pos];


            // get attribute
            strncpy (attribute, (char *)attr_start, (int)attr_len );
            attribute[(int)attr_len] = '\0';

            // get value
            strncpy (value, (char *)val_start, (int)val_len );
            value[(int)val_len] = '\0';
            format_value(formatted_value, value);

            // compute component filter, and store it
            strcat(formatted_comp_filter, "(");
            strcat(formatted_comp_filter, attribute);
            strcat(formatted_comp_filter, "=");
            strcat(formatted_comp_filter, formatted_value);
            strcat(formatted_comp_filter, ")");
            insert_filter(comp_filter, formatted_comp_filter);

            // combine format_filter parts for computing full_filter
            strncat(formatted_filter, cursor, ovector[2*attr_pos]);
            strcat(formatted_filter, attribute);
            strcat(formatted_filter, "=");
            strcat(formatted_filter, formatted_value);
            strcat(formatted_filter, ")");

            cursor += ovector[2*val_pos+1];
            cursor++;

        }
        else
        {
            fprintf(stderr,"dummy capture groupe number: %d\n",rc);
        }

    }
    pcre2_match_data_free(match_data);

    strcat(formatted_filter, cursor);
    insert_filter(full_filter, formatted_filter);
    
}

int main( int argc, char **argv )
{
    // file stuff
    FILE * fp;
    char line[LINE_MAX_SIZE];

    // regex stuff
    /* for pcre2_compile */
    pcre2_code *re, *ref;
    PCRE2_SIZE erroffset;
    int errcode;
    PCRE2_UCHAR8 buffer[128];

    /* for pcre2_match */
    int rc;
    PCRE2_SIZE* ovector;

    const char *pattern = "filter=\"([^\"]+)\"";
    size_t pattern_size = strlen(pattern);

    const char *patternf = "\\(([^=(]+)=([^)]+)\\)";
    size_t patternf_size = strlen(patternf);

    uint32_t options = 0;

    pcre2_match_data *match_data;
    uint32_t ovecsize = 128;

    // temporary string to store current filter
    char current_filter[FILTER_MAX_SIZE];

    // structures storing the filters
    sfilter *full_filter = malloc(MAX_FILTERS * sizeof(sfilter));
    sfilter *comp_filter = malloc(MAX_FILTERS * sizeof(sfilter));
    for( int i=0 ; i < MAX_FILTERS ; i++ )
    {
        full_filter[i].filter[0] = '\0';
        full_filter[i].occurrence = 0;
        comp_filter[i].filter[0] = '\0';
        comp_filter[i].occurrence = 0;
    }


    if(argc < 2)
    {
        fprintf(stderr,"Missing file name\n");
        exit(1);
    }

    re = pcre2_compile(pattern, pattern_size, options, &errcode, &erroffset, NULL);
    if (re == NULL)
    {
        pcre2_get_error_message(errcode, buffer, 120);
        fprintf(stderr,"%d\t%s\n", errcode, buffer);
        return 1;
    }

    ref = pcre2_compile(patternf, patternf_size, options, &errcode, &erroffset, NULL);
    if (ref == NULL)
    {
        pcre2_get_error_message(errcode, buffer, 120);
        fprintf(stderr,"%d\t%s\n", errcode, buffer);
        return 1;
    }


    for( int i = 1; i < argc ; i++ )
    {
        fp = fopen(argv[i], "r");
        if (fp == NULL)
        {
            fprintf(stderr,"Error while trying to open %s\n", argv[i]);
            exit(1);
        }

        // parse file
        while (fgets(line,LINE_MAX_SIZE, fp))
        {
            // only get filter="..." part
            match_data = pcre2_match_data_create(ovecsize, NULL);
            rc = pcre2_match(re, line, strlen(line), 0, options, match_data, NULL);

            if(rc == 0) {
                // error
                fprintf(stderr,"offset vector too small: %d\n",rc);
            }
            else if(rc == 2) // 2 = regex matching (1) + one matching group (1)
            {
                ovector = pcre2_get_ovector_pointer(match_data);
                PCRE2_SIZE i = 1; // first match is at position 1
                PCRE2_SPTR start = line + ovector[2*i];
                PCRE2_SIZE slen = ovector[2*i+1] - ovector[2*i];
                strncpy (current_filter, (char *)start, (int)slen );
                current_filter[(int)slen] = '\0';
                compute_filter(full_filter, comp_filter, current_filter, ref);
            }
            else if (rc < 0)
            {
                // no match
            }

            pcre2_match_data_free(match_data);

        }

        fclose(fp);
    }

    pcre2_code_free(re);
    pcre2_code_free(ref);

    sort_filters(full_filter);
    printf("| Occurrences | Full filters                                                   |\n");
    printf("+-------------+----------------------------------------------------------------+\n");
    display_filters(full_filter);

    sort_filters(comp_filter);
    printf("\n");
    printf("| Occurrences | Filter components                                              |\n");
    printf("+-------------+----------------------------------------------------------------+\n");
    display_filters(comp_filter);

    free(full_filter);
    free(comp_filter);

    exit(0);
}
