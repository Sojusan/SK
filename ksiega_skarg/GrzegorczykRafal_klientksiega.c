#define _WITH_GETLINE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <pwd.h>
#include <unistd.h>
#include <signal.h>

/*
Dodatkowo:
- klient moze zrezygnowac z wprowadzenia wpisu
- klient posiada kolorystyke
*/

#define MY_MSG_SIZE 1024

#define SIGNALS "\x1B[38;5;44m"	/* kolor sygnalow */
#define NUMBERS "\x1B[38;5;135m" /* kolor cyfr */
#define RESET "\x1B[0m"					 /* przywrocenie domyslnego koloru */

key_t shmkey;				/* klucz pamieci wspoldzielonej */
key_t semkey;				/* klucz semaforow */
int shmid;					/* identyfikator pamieci wspoldzielonej */
int semid;					/* identyfikator semaforow */
int which_one = -1; /* zmienna przechowujaca informacje o numerze zablokowanego semafora, -1 informuje o braku wolnego semafora */
struct sembuf sb;		/* struktura wykorzystywana podczas operacji na semaforach */
struct my_data
{
	int size;										/* rozmiar tablicy w pamieci wspoldzielonej */
	uid_t uid_client;						/* uid klienta ktory dokonal wpisu */
	char txt[MY_MSG_SIZE];			/* tresc dokonanego wpisu przez klienta */
} * shared_data;							/* tablica struktury do operowania na pamieci wspoldzielonej */
char *buf = NULL;							/* bufor na komunikat */
size_t bufsize = MY_MSG_SIZE; /* wielkosc bufora na komunikat */

void handle_SIGTSTP(int sig, siginfo_t *info, void *ucontext)
{
	sb.sem_num = which_one;
	sb.sem_op = 1;
	sb.sem_flg = 0;
	if (semop(semid, &sb, 1) == -1) /* zwalniam zajety semafor */
	{
		perror("Blad semop");
		exit(1);
	}
	if (shmdt(shared_data) == -1) /* odlaczam pamiec wspoldzielona */
	{
		perror("Blad shmdt");
		exit(1);
	}
	printf("\nZrezygnowano z dodania wpisu\n");
	exit(0);
}

void handle_SIGINT(int sig, siginfo_t *info, void *ucontext)
{
	sb.sem_num = which_one;
	sb.sem_op = 1;
	sb.sem_flg = 0;
	if (semop(semid, &sb, 1) == -1) /* zwalniam zajety semafor */
	{
		perror("Blad semop");
		exit(1);
	}
	if (shmdt(shared_data) == -1) /* odlaczam pamiec wspoldzielona */
	{
		perror("Blad shmdt");
		exit(1);
	}
	printf("\nZrezygnowano z dodania wpisu\n");
	exit(0);
}

int is_file(char *string) /* funkcja sprawdzajaca czy pierwszy argument jest nazwa pliku */
{
	if (access(string, F_OK) != -1)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int main(int argc, char *argv[])
{
	int i;
	/* obsluga bledow uzytkownika */
	if (argc < 2)
	{
		printf("Podano za malo parametrow!\n");
		exit(0);
	}
	else
	{
		if (argc > 2)
		{
			printf("Podano za duzo parametrow!\n");
			exit(0);
		}
		if (argc == 2)
		{
			if (!is_file(argv[1]))
			{
				printf("Podany parametr nie jest nazwa pliku!\n");
				exit(0);
			}
		}
	}
	struct sigaction sigtstp, sigint; /* sigaction do obslugi sygnalow */
	sigtstp.sa_flags = SA_SIGINFO;
	sigemptyset(&sigtstp.sa_mask);
	sigtstp.sa_sigaction = handle_SIGTSTP;
	sigint.sa_flags = SA_SIGINFO;
	sigemptyset(&sigint.sa_mask);
	sigint.sa_sigaction = handle_SIGINT;
	if (sigaction(SIGTSTP, &sigtstp, NULL) == -1)
	{
		perror("Blad sigaction(SIGTSTP)");
		exit(1);
	}
	if (sigaction(SIGINT, &sigint, NULL) == -1)
	{
		perror("Blad sigaction(SIGINT)");
		exit(1);
	}

	uid_t owner;
	owner = getuid(); /* pobieram uid klienta, ktory nastepnie zostanie przeslany do serwera */
	/* tworze klucz semaforow */
	if ((semkey = ftok(argv[1], 2)) == -1)
	{
		perror("Blad semkey (ftok)!");
		exit(1);
	}
	printf("Klient ksiegi skarg i wnioskow wita!\n");
	/* tworze klucz pamieci wspoldzielonej */
	if ((shmkey = ftok(argv[1], 1)) == -1)
	{
		perror("Blad shmkey (ftok)!");
		exit(1);
	}
	/* otwieram segment pamieci wspolnej */
	if ((shmid = shmget(shmkey, 0, 0)) == -1)
	{
		perror("Blad shmget");
		exit(1);
	}
	/* dolaczam pamiec wspolna */
	shared_data = (struct my_data *)shmat(shmid, (void *)0, 0);
	if (shared_data == (struct my_data *)-1)
	{
		printf("Blad shmat!\n");
		exit(1);
	}
	/* pobieram utworzone semafory */
	if ((semid = (semget(semkey, shared_data->size, 0))) == -1)
	{
		perror("Blad semget!");
		exit(1);
	}
	/* sprawdzam ile semaforow jest zajetych */
	int in_use = 0;
	for (i = 0; i < shared_data->size; i++)
	{
		sb.sem_num = i;
		sb.sem_op = -1;
		sb.sem_flg = IPC_NOWAIT; /* dzieki tej fladze zwracany jest blad EAGAIN gdzie semafor normalnie by sie zatrzymal */
		if (semop(semid, &sb, 1) == -1)
		{
			if (errno == EAGAIN) /* jezeli natrafi na EAGAIN, czyli semafor zajety to sprawdza kolejny */
			{
				in_use++;
				continue;
			}
			perror("Blad semop");
			exit(1);
		}
		/* podczas sprawdzania otwarte semafory sa zamykane wiec spowrotem je otwieram */
		sb.sem_num = i;
		sb.sem_op = 1;
		sb.sem_flg = 0;
		if (semop(semid, &sb, 1) == -1)
		{
			perror("Blad semop");
			exit(1);
		}
	}
	/* blokuje pierwszy wolny semafor */
	for (i = 0; i < shared_data->size; i++)
	{
		sb.sem_num = i;
		sb.sem_op = -1;
		sb.sem_flg = IPC_NOWAIT; /* dzieki tej fladze zwracany jest blad EAGAIN gdzie semafor normalnie by sie zatrzymal */
		if (semop(semid, &sb, 1) == -1)
		{
			if (errno == EAGAIN) /* jezeli natrafi na EAGAIN, czyli semafor zajety to sprawdza kolejny */
			{
				continue;
			}
			perror("Blad semop");
			exit(1);
		}
		which_one = i;
		break;
	}
	printf("[Wolnych " NUMBERS "%d" RESET " wpisow (na " NUMBERS "%d" RESET ")]\n", (shared_data->size - in_use), shared_data->size);
	if (which_one == -1)
	{
		printf("Brak miejsca w ksiedze na wpis\n");
	}
	else
	{
		printf("Nacisnij " SIGNALS "Ctrl^Z" RESET " lub " SIGNALS "Ctrl^C" RESET " by zrezygnowac z wpisu...\n");
		printf("Podaj tresc wpisu do ksiegi:\n> ");
		getline(&buf, &bufsize, stdin);
		buf[strlen(buf) - 1] = '\0'; /* techniczne: usuwam koniec linii */
		strcpy(shared_data[which_one].txt, buf);
		shared_data[which_one].uid_client = owner;
		printf("Dziekuje za dokonanie wpisu do ksiegi\n");
	}
	if (shmdt(shared_data) == -1) /* odlaczam pamiec wspoldzielona */
	{
		perror("Blad shmdt");
		exit(1);
	}
	return 0;
}
