.PHONY: all re clear fclear

SRCDIR=./src/
OBJDIR=./obj/
INCDIR=./inc/

SRC=main.c
OBJ=$(patsubst $(SRCDIR)%.c,$(OBJDIR)%.o,$(SRC))
INC=$(addprefix $(INCDIR), corsair.h)

NAME=coRSAir

CXX=gcc
CXXFLAGS=-Wall -Werror -Wextra

all:	$(NAME)

$(NAME):	$(OBJ) $(INC)
	@$(CXX) $(CXXFLAGS) -o $(NAME) $(OBJ) -I$(INCDIR)

$(OBJDIR)%.o:	$(SRCDIR)%.c
	@$(CXX) $(CXXFLAGS) -c $<
	@mkdir -p $(OBJDIR)
	@mv $< $(@D)


# ~  aesthetica ~
GREEN="\e[32m"
RED="\e[31m"
CYAN="\e[36m"
END="\e[0m"
# ~      **     ~
