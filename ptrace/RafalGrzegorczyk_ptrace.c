/* Rafal Grzegorczyk */
/* program napisany na architekturze x86-64 */
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <ctype.h>

void change(char *str, int len) /* funkcja podstawiajaca nowe zdanie w miejsce str */
{
	//char* temp2 = "Ptrace rzadzi\n"; /* zdanie ktore zostanie podstawione */
	//strcpy(str, temp2);
	int i = 0;
	for (i = 0; i < len; i++)
	{
		str[i] = toupper(str[i]);
	}
}

void getdata(pid_t child, long addr, char *str, int len) /* funkcja wczytujaca dane */
{
	int i, j;										/* poniewaz dane wczytujemy po 8 bitow (wielkosc long w systemie), j - okresla ilosc wykonan w celu wczytania wszystkich danych */
	union u {										/* unia sluzaca do wczytania danych */
		long val;									/* zmienna sluzaca do pobrania wartosci z PEEKDATA */
		char chars[sizeof(long)]; /* unia posluguje sie tym samym miejscem w pamieci wiec mamy dostep do napisu */
	} data;
	i = 0;
	j = len / sizeof(long);
	while (i < j)
	{
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * sizeof(long), NULL); /* PEEKDATA sluzy do wczytania danych */
		memcpy(str, data.chars, sizeof(long));																		/* kopiuje z pamieci wczytany napis do str */
		++i;
		str += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0)
	{
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * sizeof(long), NULL);
		memcpy(str, data.chars, j);
	}
	str[len] = '\0';
}

void putdata(pid_t child, long addr, char *str, int len) /* funkcja wpisujaca dane */
{
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;
	i = 0;
	j = len / sizeof(long);
	while (i < j)
	{
		memcpy(data.chars, str, sizeof(long));
		ptrace(PTRACE_POKEDATA, child, addr + i * sizeof(long), data.val); /* POKEDATA sluzy do zapisania danych */
		++i;
		str += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0)
	{
		memcpy(data.chars, str, j);
		ptrace(PTRACE_POKEDATA, child, addr + i * sizeof(long), data.val);
	}
}

int main()
{
	pid_t child;
	child = fork();
	if (child == 0)
	{
		ptrace(PTRACE_TRACEME, 0, NULL, NULL); /* TRACEME ustawiam sledzenie procesu */
																					 //execl("/bin/echo", "echo", "Witaj swiecie!", NULL);
		execl("/bin/ls", "ls", "-la", NULL);
	}
	else
	{
		long orig_rax; /* zmienna do sprawdzania czy wywolanie systemowe jest SYS_write(1) czyli pisaniem */
		int status;
		char *str;
		int toggle = 0; /* proces zostanie zatrzymany podwojnie przy poczatku oraz koncu wywolania systemowego
	       			   wiec korzystam ze zmiennej by wykonac podmiane tylko raz */
		while (1)
		{
			wait(&status);				 /* czeka az proces potomny sie zatrzyma */
			if (WIFEXITED(status)) /* jesli proces potomny zakonczyl sie, wyjdz z while */
				break;
			orig_rax = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX, NULL); /* pobranie informacji o numerze wywolania systemowego */
			if (orig_rax == SYS_write)																								/* w 64-bitowym systemie SYS_write ma wartosc 1 */
			{
				if (toggle == 0)
				{
					toggle = 1;
					struct user_regs_struct regs;								/* struktura zawierajaca rejestry procesu */
					ptrace(PTRACE_GETREGS, child, NULL, &regs); /* GETREGS sluzy do pobrania informacji o rejestrach */
					str = (char *)malloc((regs.rdx + 1) * sizeof(char));
					getdata(child, regs.rsi, str, regs.rdx);
					/* RSI - Source Index (rejestr zrodlowy - trzyma zrodlo lancucha danych) */
					/* RDX - Data Register (rejestr danych - umozliwia przekaz/odbior danych z portow wejscia/wyjscia) */
					/* RSI - adres na lancuch, RDX - informacja o dlugosci lancucha znakow */
					change(str, regs.rdx);
					putdata(child, regs.rsi, str, regs.rdx);
				}
				else
				{
					toggle = 0;
				}
			}
			ptrace(PTRACE_SYSCALL, child, NULL, NULL); /* SYSCALL restart zatrzymanego procesu i ponownego jego zatrzymanie przy kolejnym wywolaniu systemowym */
		}
	}
	return 0;
}
