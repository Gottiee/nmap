#ifndef ERROR_H
#define ERROR_H

void fatal_error(char *err);
void fatal_perror(char *err);
void fatal_error_str(char *message, char *err);

#endif