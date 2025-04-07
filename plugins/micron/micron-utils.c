/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) Micron, Inc 2024.
 * 
 * @file: micron-utils.h
 * @brief: This module contains all the utilities needed for micron nvme plugin and other micron modules.
 * @author: Chaithanya Shoba <ashoba@micron.com>
 */

#include "micron-utils.h"

int hex_to_int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    else if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    else
        return -1; // Invalid character
}

char* hex_to_ascii(const char* hex) 
{
    int hexLength = strlen(hex);
    char* text = NULL;

    if (hexLength > 0) {
        int symbolCount;
        int oddHexCount = hexLength % 2 == 1;

        if (oddHexCount)
            symbolCount = (hexLength / 2) + 1;
        else
            symbolCount = hexLength / 2;

        text = (char*)malloc(symbolCount + 1); // Allocate memory for the result

        int lastIndex = hexLength - 1;
        for (int i = lastIndex; i >= 0; --i) {
            if ((lastIndex - i) % 2 != 0) {
                int dec = 16 * hex_to_int(hex[i]) + hex_to_int(hex[i + 1]);
                if (oddHexCount)
                    text[i / 2 + 1] = dec;
                else
                    text[i / 2] = dec;
            } else if (i == 0) {
                int dec = hex_to_int(hex[0]);
                text[0] = dec;
            }
        }

        text[symbolCount] = '\0'; // Terminate the string
    }

    return text;
}
    
unsigned char *read_binary_file(char *data_dir_path, const char *bin_path, long *buffer_size, int retry_count)
{
    char *file_path = NULL;
    FILE *bin_file = NULL;
    size_t n_data = 0;
    unsigned char *buffer = NULL;

    /* set path */
    if (data_dir_path == NULL)
    {
        file_path = (char *)bin_path;
    }
    else
    {
        /* +2 for the / and null terminator */
        file_path = (char *) calloc(1, strlen(data_dir_path) + strlen(bin_path) + 2);
        if (!file_path)
        {
            return NULL;
        }
        if (strlen(bin_path) != 0)
        {
            sprintf(file_path, "%s/%s", data_dir_path, bin_path);
        }
        else
        {
            sprintf(file_path, "%s", data_dir_path);
        }
    }

    /* open file */
    for (int i = 0; i < retry_count; i++)
    {
        if ((bin_file = fopen(file_path, "rb")) != NULL)
        {
            break;
        }
        sleep((unsigned int)(retry_count > 1));
    }

    if (!bin_file)
    {
        nvme_show_error("\nFailed to open %s", file_path);
        if (file_path != bin_path)
        {
            free(file_path);
        }
        goto ret_null;
    }

    /* get size */
    fseek(bin_file, 0, SEEK_END);
    *buffer_size = ftell(bin_file);
    fseek(bin_file, 0, SEEK_SET);
    if (*buffer_size <= 0) {
        fclose(bin_file);
        return NULL;
    }
    
    /* allocate buffer */
    buffer = (unsigned char *)malloc(*buffer_size);
    if (!buffer)
    {
        nvme_show_result("\nFailed to allocate %ld bytes!", *buffer_size);
        fclose(bin_file);
        goto ret_null;
    }
    memset(buffer, 0, *buffer_size);

    /* Read data */
    n_data = fread(buffer, 1, *buffer_size, bin_file);

    /* Close file */
    fclose(bin_file);

    /* Validate we read data */
    if (n_data != (size_t)*buffer_size)
    {
        nvme_show_result("\nFailed to read %ld bytes from %s", *buffer_size, file_path);
        goto ret_null;
    }

    if (file_path != bin_path)
    {
        free(file_path);
    }
    return(buffer);
ret_null:
    return(NULL);
}

void print_formatted_var_size_str(const char *msg, const __u8 *pdata, size_t data_size, FILE *fp)
{
    char description_str[256] = "";
    char temp_buffer[3] = { 0 };

    for (size_t i = 0; i < data_size; ++i) {
        sprintf(temp_buffer, "%02X", pdata[i]);
        strcat(description_str, temp_buffer);
    }

    if (fp) {
        fprintf(fp, "%s: %s\n", msg, description_str);
    } else {
        printf("%s: %s\n", msg, description_str);
    }
}


void print_micron_vs_logs(__u8 *buf, struct micron_vs_logpage *log_page, int field_count,
				 struct json_object *stats, __u8 spec, FILE *fp)
{
	__u64 lval_lo, lval_hi;
	__u32 ival;
	__u16 sval;
	__u8  cval, lval[8] = { 0 };
	int field;
	int offset = 0;

	for (field = 0; field < field_count; field++) {
		char datastr[1024] = { 0 };
		char *sfield = NULL;
		int size = !spec ? log_page[field].size : log_page[field].size2;

		if (!size)
			continue;
		sfield = log_page[field].field;
        if (size == 16) {
			if (strstr(sfield, "GUID")) {
				sprintf(datastr, "0x%"PRIx64"%"PRIx64"",
						(uint64_t)le64_to_cpu(*(uint64_t *)(&buf[offset + 8])),
						(uint64_t)le64_to_cpu(*(uint64_t *)(&buf[offset])));
			} else {
				lval_lo = *((__u64 *)(&buf[offset]));
				lval_hi = *((__u64 *)(&buf[offset + 8]));
				if (lval_hi)
					sprintf(datastr, "0x%"PRIx64"%016"PRIx64"",
						le64_to_cpu(lval_hi), le64_to_cpu(lval_lo));
				else
					sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
			}
		} else if (size == 8) {
        	if (strstr(sfield, "Boot SSD Spec Version")) {
        		sprintf(datastr, "%x.%x.%x.%x",
        				le16_to_cpu(*((__u16 *)(&buf[300]))),
                    	le16_to_cpu(*((__u16 *)(&buf[302]))),
                    	le16_to_cpu(*((__u16 *)(&buf[304]))),
                    	le16_to_cpu(*((__u16 *)(&buf[306]))));
        	} else if (strstr(sfield, "Firmware Revision")){
                char buffer[30] = {'\0'};
                lval_lo = *((__u64 *)(&buf[offset]));
                sprintf(buffer, "%lx", __builtin_bswap64(lval_lo));
			    sprintf(datastr, "%s", hex_to_ascii(buffer));
            } else if (strstr(sfield, "Timestamp")){
                lval_lo = *((__u64 *)(&buf[offset]));
                char ts_buf[128];
                convert_ts(le64_to_cpu(lval_lo), ts_buf);
                sprintf(datastr, "%s", ts_buf);
            } else {
        		lval_lo = *((__u64 *)(&buf[offset]));
        		sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
        	}
        } else if (size == 7) {
            /* 7 bytes will be in little-endian format, with last byte as MSB */
            memcpy(&lval[0], &buf[offset], 7);
            memcpy((void *)&lval_lo, lval, 8);
            sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
        } else if (size == 6) {
            if (strstr(sfield, "DSSD Spec Version")) {
        		sprintf(datastr, "%x.%x.%x.%x",
        				buf[103],
           	    le16_to_cpu(*((__u16 *)(&buf[101]))),
                le16_to_cpu(*((__u16 *)(&buf[99]))),
                buf[98]);
        	  } else {
               ival    = *((__u32 *)(&buf[offset]));
               sval    = *((__u16 *)(&buf[offset + 4]));
               lval_lo = (((__u64)sval << 32) | ival);
               sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
            }
		} else if (size == 4) {
			ival	= *((__u32 *)(&buf[offset]));
			sprintf(datastr, "0x%x", le32_to_cpu(ival));
        } else if (size == 3) {
			sprintf(datastr, "0x%02X%02X%02X",  buf[offset + 0], buf[offset + 1], buf[offset + 2]);
		} else if (size == 2) {
			sval = *((__u16 *)(&buf[offset]));
			sprintf(datastr, "0x%04x", le16_to_cpu(sval));
		} else if (size == 1) {
			cval = buf[offset];
			sprintf(datastr, "0x%02x", cval);
  	    }        
        else {
            char description_str[256] = "0x";
            char temp_buffer[3] = { 0 };

            for (unsigned char i = 0; i < (unsigned char)size; i++) 
            {
                cval = (buf[offset + i]);
                sprintf(temp_buffer, "%02X", cval);
                strcat(description_str, temp_buffer);
            }
            sprintf(datastr, "%s", description_str);	   
		}
		offset += size;
		/* do not print reserved values */
		if (strstr(sfield, "Reserved"))
			continue;
		if (stats) {
            json_object_add_value_string(stats, sfield, datastr);
        }
        else if(fp){
            fprintf(fp, "%-40s : %-4s\n", sfield, datastr);
        }			
		else
			printf("%-40s : %-4s\n", sfield, datastr);
	}
}