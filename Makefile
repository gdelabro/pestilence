# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2020/10/23 19:47:08 by gdelabro          #+#    #+#              #
#    Updated: 2021/03/27 00:37:47 by gdelabro         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = war

SRC = asm/famine.s

OBJ_PATH = obj

all: $(NAME)

$(NAME): $(SRC)
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	@(nasm -f elf64 asm/famine.s -o $(OBJ_PATH)/famine.o && \
	ld -m elf_x86_64 -e $(NAME) $(OBJ_PATH)/famine.o -o $(NAME) &&\
	echo "Compilation of \033[34;1m$(NAME)\033[0;1m: [\033[1;32mOK\033[0;1m]\033[0m") || echo echo "Compilation of \033[31;1m$(NAME)\033[0;1m: [\033[1;31mKO\033[0;1m]\033[0m"

clean:
	@rm -rf $(OBJ_PATH)
	@echo "\033[33;1m$(NAME)\033[0;1m: objects deleted"

fclean: clean
	@rm -rf $(NAME)
	@echo "\033[33;1m$(NAME)\033[0;1m: $(NAME) deleted"

re: fclean all

.PHONY: all clean fclean re asm
