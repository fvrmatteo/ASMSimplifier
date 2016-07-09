/*
	Name: str_replace
	Description: this function will replace 'str1' with 'str2' in a given input string.
	ignore_match specifies the index of a match that doesn't need to be replaced.
*/
char* str_replace(char *str, char *str1, char *str2, uint8_t ignore_match) {
	size_t count = 0, match = 0, str_len = strlen(str), str1_len = strlen(str1), str2_len = strlen(str2);
	//determine new space to allocate
	char *tmp = str;
	while((tmp = strstr(tmp, str1))) {
		tmp += str1_len;
		count++;
	}
	//printf("count: %d\n", count);
	//allocare new string
	char *res = calloc(str_len + str2_len * count + 1, sizeof(char));
	//substitute 'str1' with 'str2' inside 'str'
	char *tmp1 = res;
	while((tmp = strstr(str, str1))) {
		count = tmp - str;
		memcpy(tmp1, str, count);
		tmp1 += count;
		str += (count + str1_len);
		if(match++ == ignore_match) {
			strcat(tmp1, str1);
			tmp1 += str1_len;
		} else {
			strcat(tmp1, str2);
			tmp1 += str2_len;
		}
	}
	strcat(tmp1, str);
	//resize the allocated space
	str_len = strlen(res);
	res = realloc(res, str_len + 1);
	res[str_len] = '\0';
	//return the new string
	return res;
}

/*
	Name: str_between
	Description: this function will return a substring extracted from 'str' starting
	from 'str1' and arriving to 'str2'
*/
char *str_between(char *str, char *str1, char *str2) {
	if(!str || !str1 || !str2) return NULL;
	char *left = strstr(str, str1) + strlen(str1);
	if(!left) return NULL;
	char *right = strstr(left, str2);
	if(!right) return NULL;
	char *between = calloc(right - left + 1, sizeof(char));
	memcpy(between, left, right - left);
	return between;
}