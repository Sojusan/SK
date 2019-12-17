#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <signal.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

/*
Dodatkowo:
- serwer nadpisuje komunikaty, gdy otrzymuje sygnal Ctrl+Z
- serwer posiada kolorystyke
 */

#define MY_MSG_SIZE 1024

#define DL "\33[2K" /* unun linie (DL - Delete Line)*/
#define MU "\33[A"	/* przejdz do lini wyzej (MU - Move Up)*/
#define R "\r"			/* powrot na poczatek linii */

#define SIGNALS "\x1B[38;5;44m"		 /* kolor sygnalow */
#define MY_CHOICE "\x1B[38;5;196m" /* kolor wybranego wariantu zadania */
#define SERWER "\x1B[38;5;220m"		 /* kolor napisu serwer */
#define OK "\x1B[38;5;46m"				 /* kolor "OK" */
#define NUMBERS "\x1B[38;5;135m"	 /* kolor cyfr */
#define RESET "\x1B[0m"						 /* przywrocenie domyslnego koloru */

int line_overwrite_count = 0; /* zmienna informujaca ile linii nalezy sie cofnac */
int book_was_written = 0;			/* czy ksiega byla juz napisana */
int empty_was_written = 0;		/* czy brak wpisow byl juz napisany */

key_t shmkey;						 /* klucz pamieci wspoldzielonej */
key_t semkey;						 /* klucz semaforow */
int shmid;							 /* identyfikator pamieci wspoldzielonej */
int semid;							 /* identyfikator semaforow */
int num_of_el;					 /* zmienna przechowujaca ilosc elementow */
struct sembuf sb;				 /* struktura wykorzystywana podczas operacji na semaforach */
#if defined(__FreeBSD__) /* sprawdzam na ktorym jestem systemie, ultra60(FreeBSD) zawiera juz unie semun */
union semun arg;
#else /* jezeli jestem na aleks-2(Linux) tworze unie semun */
union semun {
	int val;
	struct semid_ds *buf;
	ushort *array;
} arg; /* unia potrzebna podczas operowania na semaforach (np podczas usuwania) */
#endif
struct my_data
{
	int size;							 /* rozmiar tablicy w pamieci wspoldzielonej */
	uid_t uid_client;			 /* uid klienta ktory dokonal wpisu */
	char txt[MY_MSG_SIZE]; /* tresc dokonanego wpisu przez klienta */
} * shared_data;				 /* tablica struktury do operowania na pamieci wspoldzielonej */

void handle_SIGTSTP(int sig, siginfo_t *info, void *ucontext) /* obsluga sygnalu do wypisania aktualnych wpisow */
{
	int is_empty = 1; /* zmienna pomocnicza do sprawdzania czy ksiega jest pusta */
	int i;
	int new_line_overwrite_count = 0; /* licze ile bedzie linii w kolejnym wypisaniu */
	for (i = 0; i < shared_data->size; i++)
	{
		if (shared_data[i].uid_client != -1)
		{
			is_empty = 0;
			new_line_overwrite_count++;
		}
	}
	struct passwd *owner;
	if (is_empty == 1)
	{
		if (empty_was_written == 0)
		{
			empty_was_written = 1;
			printf("\nKsiega skarg i wnioskow jest jeszcze pusta\n");
		}
		else
		{
			printf(DL R);
			//printf("\33[2K\33[A\33[2K\33[A\33[2K\r^Z\nKsiega skarg i wnioskow jest jeszcze pusta\n");
			fflush(stdout); /* potrzebne by nadpisanie sie udalo */
		}
	}
	else
	{
		if (book_was_written == 0)
		{
			book_was_written = 1;
			if (empty_was_written == 0)
			{
				printf("\n___________  Ksiega skarg i wnioskow:  ___________\n");
			}
			else
			{
				printf(DL MU R);
				printf("___________  Ksiega skarg i wnioskow:  ___________\n");
				fflush(stdout);
			}
		}
		else
		{
			for (i = 0; i < line_overwrite_count; i++)
			{
				printf(DL MU);
			}
			printf(DL R);
			fflush(stdout);
		}

		for (i = 0; i < shared_data->size; i++)
		{
			if (shared_data[i].uid_client != -1)
			{
				if ((owner = getpwuid(shared_data[i].uid_client)) == NULL)
				{
					perror("Blad podczas pobrania nazwy uzytkownika");
					exit(1);
				}
				printf("[%s]: ", owner->pw_name);
				printf("%s\n", shared_data[i].txt);
			}
		}
	}
	line_overwrite_count = new_line_overwrite_count; /* podmieniam stara ilosc linii na nowa */
}

void handle_SIGINT(int sig, siginfo_t *info, void *ucontext) /* obsluga sygnalu konczacego prace serwera */
{
	printf("\n[" SERWER "Serwer" RESET "]: dostalem " SIGNALS "SIGINT" RESET " => koncze i sprzatam...");
	printf(" (odlaczenie pamieci: %s, usuniecie pamieci: %s, usuniecie semaforow: %s\n",
				 (shmdt(shared_data) == 0) ? OK "OK" RESET : "Blad shmdt",
				 (shmctl(shmid, IPC_RMID, 0) == 0) ? OK "OK" RESET : "Blad shmctl",
				 (semctl(semid, 0, IPC_RMID, arg) == 0) ? OK "OK" RESET ")" : "Blad semctl)");
	exit(0);
}

int is_number(char *string) /* funkcja sprawdzajaca czy drugi argument jest liczba */
{
	int i;
	for (i = 0; i < strlen(string); i++)
	{
		if (!isdigit(string[i]))
		{
			return 0;
		}
	}
	return 1;
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
	if (argc < 3)
	{
		printf("Podano za malo parametrow !\n");
		exit(0);
	}
	else
	{
		if (argc > 3)
		{
			printf("Podano za duzo parametrow !\n");
			exit(0);
		}
		if (argc == 3)
		{
			if (!is_number(argv[2]))
			{
				printf("Drugi parametr nie jest liczba!\n");
				exit(0);
			}
			if (!is_file(argv[1]))
			{
				printf("Pierwszy parametr nie jest nazwa pliku!\n");
				exit(0);
			}
		}
	}
	struct shmid_ds buf; /* struktura potrzebna do pobrania informacji o rozmiarze pamieci wspoldzielonej */
	num_of_el = atoi(argv[2]);

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

	printf("[" SERWER "Serwer" RESET "]: ksiega skarg i wnioskow (" MY_CHOICE "WARIANT A" RESET ")\n");
	printf("[" SERWER "Serwer" RESET "]: tworze klucz pamieci wspoldzielonej...");
	if ((shmkey = ftok(argv[1], 1)) == -1)
	{
		perror("Blad shmkey (ftok)!");
		exit(1);
	}
	printf(" " OK "OK" RESET " (klucz: " NUMBERS "%ld" RESET ")\n", (long)shmkey);
	printf("[" SERWER "Serwer" RESET "]: tworze klucz semaforow...");
	if ((semkey = ftok(argv[1], 2)) == -1)
	{
		perror("Blad semkey (ftok)!");
		exit(1);
	}
	printf(" " OK "OK" RESET " (klucz: " NUMBERS "%ld" RESET ")\n", (long)semkey);
	printf("[" SERWER "Serwer" RESET "]: tworze semafory...");
	if ((semid = (semget(semkey, num_of_el, 0666 | IPC_CREAT | IPC_EXCL))) == -1)
	{
		perror("Blad semget!");
		exit(1);
	}
	printf(" " OK "OK" RESET " (id: " NUMBERS "%d" RESET ")\n", semid);
	for (i = 0; i < num_of_el; i++) /* zwalniam wszystkie utworzone semafory */
	{
		sb.sem_num = i; /* numer semafora */
		sb.sem_op = 1;	/* operacja na semaforze */
		sb.sem_flg = 0; /* flaga semafora */
		if (semop(semid, &sb, 1) == -1)
		{
			perror("Blad semop!");
			exit(1);
		}
	}
	printf("[" SERWER "Serwer" RESET "]: tworze segment pamieci wspolnej dla ksiegi na " NUMBERS "%d" RESET " wpisow...", num_of_el);
	if ((shmid = shmget(shmkey, num_of_el * sizeof(struct my_data), 0666 | IPC_CREAT | IPC_EXCL)) == -1)
	{
		perror("Blad shmget!\n");
		exit(1);
	}
	shmctl(shmid, IPC_STAT, &buf); /* pobranie statystyk do struktury buf */
	printf(" " OK "OK" RESET " (id: " NUMBERS "%d" RESET ", rozmiar: " NUMBERS "%zub" RESET ")\n", shmid, buf.shm_segsz);
	printf("[" SERWER "Serwer" RESET "]: dolaczam pamiec wspolna...");
	shared_data = (struct my_data *)shmat(shmid, (void *)0, 0);
	if (shared_data == (struct my_data *)-1)
	{
		printf("Blad shmat!\n");
		exit(1);
	}
	printf(" " OK "OK" RESET " (adres: " NUMBERS "%lX" RESET ")\n", (long int)shared_data);
	printf("[" SERWER "Serwer" RESET "]: nacisnij " SIGNALS "Crtl^Z" RESET " by wyswietlic stan ksiegi...\n");
	printf("[" SERWER "Serwer" RESET "]: nacisnij " SIGNALS "Crtl^C" RESET " by wylaczyc ksiege...\n");
	shared_data->size = num_of_el; /* wpisanie do pamieci wspoldzielonej informacji o ilosci elementow */
	/* wstawiam uid_client = -1 by miec informacje o braku wpisow
	 uid nie moze byc ujemny wiec mam pewnosc ze takiej wartosci klient nie zwroci */
	for (i = 0; i < shared_data->size; i++)
	{
		shared_data[i].uid_client = -1;
	}
	/* Serwer dziala i oczekuje na sygnaly */
	while (1)
	{
		pause();
	}
	return 0;
}
