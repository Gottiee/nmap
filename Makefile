# VARIABLES

NAME		=	ft_nmap

SRC_DIR		= 	src/
OBJ_DIR		= 	obj/

SUBDIR		=	obj/network

CC			= gcc
CFLAGS		= -lm -Wall -Werror -Wextra -g -O0 -MMD -MP

RM			= rm -rf
AR			= ar rcs
SAN			= -fsanitize=address

# SOURCES

SRC_FILES = nmap \
error \
handle_arg \
thread \
network/network \
network/UDP \
network/TCP \
network/analyse_packet \
icmp \
utils \
print \
service


C_FILES		=	$(addsuffix .c, $(SRC_FILES))
SRCS		=	$(addprefix $(SRC_DIR), $(C_FILES))
OBJS		=	$(addprefix $(OBJ_DIR), $(C_FILES:.c=.o))
DEPS		=	$(OBJS:.o=.d)

#	LOAD BAR

COUNT	:= $(words $(SRC_FILES))
LOAD	= 0
SPACE = $(COUNT)

#	 MANDATORY
all:		 obj $(NAME)
			

$(NAME):	$(OBJS)
			@$(CC) $(CFLAGS) $^ -o $@ -lpcap
			@echo "$(FONT_BOLD)FILES LOAD ! $(FONT_RESET)    $(COUNT)/($(COUNT))"
			@echo "$(RED)$(NAME) compiled !$(DEF_COLOR)"

$(OBJ_DIR)%.o:	 $(SRC_DIR)%.c 
			@$(CC) $(CFLAGS) $(ADDFLAGS) -c -o $@ $< 
			@echo "$(BLUE)Creating object file -> $(MAGENTA)$(notdir $@)... $(RED)[Done]$(NOC)"

#	BONUS
bonus:		obj $(LIB) $(NAME_BONUS)

#	 RULES
obj:
			@mkdir -p $(OBJ_DIR)
			@mkdir -p $(SUBDIR)

clean:
			@$(RM) $(OBJ_DIR) $(DEPS_DIR)
			@echo "$(BLUE)$(NAME) object files cleaned!$(DEF_COLOR)"

fclean:		clean
			@$(RM) -f $(NAME) 

re:			fclean
			@make --no-print-directory all
			@echo "$(GREEN)Cleaned and rebuilt everything for $(NAME)!$(DEF_COLOR)"

.PHONY: all clean fclean re	

-include $(DEPS)

# COLORS

NOC = \033[0m
BOLD = \033[1m
UNDERLINE = \033[4m
DEF_COLOR = \033[0;39m
GRAY = \033[0;90m
RED = \033[0;91m
GREEN = \033[0;92m
YELLOW = \033[0;93m
BLUE = \033[0;94m
MAGENTA = \033[0;95m
CYAN = \033[0;96m
WHITE = \033[0;97m
FONT_BOLD := $(shell tput bold)
FONT_RED := $(shell tput setaf 1)
FONT_RESET := $(shell tput sgr0)
FONT_CYAN := $(shell tput setaf 6)