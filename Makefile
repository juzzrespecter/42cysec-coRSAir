.PHONY: all re clear fclear

DIR_SRC=./src/
DIR_OBJ=./obj/
DIR_INC=./inc/

SRC=corsair.c \
	parse_certificate.c \
	mcd.c \
	gpk.c \
	write_to_disk.c \
	utils.c

OBJ=$(patsubst %.c,$(DIR_OBJ)%.o,$(SRC))
INC=$(addprefix $(DIR_INC), corsair.h)

NAME=coRSAir

ifeq ($(uname),Linux)
LIB_SSL=/usr/local/lib
INC_SSL=/usr/local/include
else
include .env
endif

ifdef DEBUG
DEBUGF=-DDEBUG -fsanitize=address
endif

CXX=gcc
CXXFLAGS=-Wall -Werror -Wextra -Wno-deprecated ${DEBUGF}
LIB= -lssl -lcrypto -L$(LIB_SSL)

all:	$(NAME)

$(NAME):	$(OBJ) $(INC) Makefile
ifndef LIB_SSL
	$(error Please set up openssl library path in env. for MacOs)
endif
	@$(CXX) $(CXXFLAGS) -o $(NAME) $(OBJ) -I$(DIR_INC) $(LIB)
	@echo ${GREEN} [ ok ] ${END} "✨ $@: built successfully ✨"

$(DIR_OBJ)%.o:	$(DIR_SRC)%.c
	@mkdir -p $(@D)
	@$(CXX) $(CXXFLAGS) -I$(INC_SSL) -I $(DIR_INC) -c $< -o $@
	@echo ${CYAN} [ ok ] ${END} "$@: compiled"

$(DIR_SRC)%.c:
	@echo ${RED} "[error] " ${END} "$@: file not found"

clean:
	@rm -f $(NAME)
	@echo ${RED} [ rm ] ${END} "$(NAME): removed"

fclean:	clean
	@rm -rf $(DIR_OBJ)
	@echo ${RED} [ rm ] ${END} "$(DIR_OBJ): removed"

re: fclean all
# ~  aesthetica ~
GREEN="\033[32m"
RED="\033[31m"
CYAN="\033[36m"
END="\033[0m"
# ~      **     ~
