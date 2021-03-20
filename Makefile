# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2020/10/23 19:47:08 by gdelabro          #+#    #+#              #
#    Updated: 2021/03/20 16:40:56 by gdelabro         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = Famine

SRC_PATH = src
SRC_NAME = main.c process_file.c check_address.c check_already_infected.c\
check_proc.c

OBJ_PATH = obj
OBJ_NAME = $(SRC_NAME:.c=.o)

CC = gcc
CFLAGS = -Wall -Werror -Wextra

SRC = $(addprefix $(SRC_PATH)/,$(SR_NAME))
OBJ = $(addprefix $(OBJ_PATH)/,$(OBJ_NAME))

all: asm#$(NAME)

$(NAME): $(OBJ)
	@printf "\n"
	@$(CC) $^ -o $@
	@echo "Compilation of \033[33;1m$(NAME)\033[0;1m: [\033[1;32mOK\033[0;1m]\033[0m"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c
	@printf "\033[34;1m| \033[0;1m"
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	@$(CC) $(CFLAGS) -c $< -o $@

asm:
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	@(nasm -f elf64 asm/famine.s -o $(OBJ_PATH)/famine.o && \
	ld -m elf_x86_64 -e $(NAME) $(OBJ_PATH)/famine.o -o $(NAME) &&\
	echo "Compilation of \033[33;1m$(NAME)\033[0;1m: [\033[1;32mOK\033[0;1m]\033[0m") || echo echo "Compilation of \033[33;1m$(NAME)\033[0;1m: [\033[1;32mKO\033[0;1m]\033[0m"
	@

clean:
	@rm -f $(OBJ)
	@rm -rf $(OBJ_PATH)
	@echo "\033[33;1m$(NAME)\033[0;1m: objects deleted"

fclean: clean
	@rm -rf $(NAME)
	@rm -rf woody
	@echo "\033[33;1m$(NAME)\033[0;1m: $(NAME) deleted"

re: fclean all

.PHONY: all clean fclean re asm
