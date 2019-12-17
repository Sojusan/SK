#include <sys/types.h> /* Typy zmiennych uzywane w systemie */
#include <sys/stat.h> /* Funkcja stat pozwalajaca pobrac informacje o pliku */
#include <stdio.h> /* Standard input/output */
#include <unistd.h> /* Standardowe funkcje unixa */
#include <dirent.h> /* Funkcje i definicje pozwalajace uzywac struktury direntry */
#include <string.h> /* Funkcje pozwalajce manipulowac lancuchami  */
#include <stdlib.h> /* Biblioteka standardowa C */
#include <time.h> /* Funkcje pozwalajace manipulowac czasem */
#include <pwd.h> /* Struktura passwd i funkcje do manipulacji nia */
#include <grp.h> /* Struktura group i funkcje do manipulacji nia */
#include <fcntl.h> /* Kontrolne funkcje systemowe */
#include <limits.h> /* PATH_MAX do czytania sciezki */

/* Kolory plikow zgodne z Linux Fedora */
/* Plik z informacja o kolorach w systemie: /etc/DIR_COLORS */
/* Kolory opsiane w zmiennej srodowiskowej LS_COLORS */
#define DIRECTORY "\x1B[38;5;33m" /* Kolor katalogow */
#define LINK "\x1B[38;5;51m" /* Kolor linku symbolicznego */
#define PIPE "\x1B[40;38;5;11m"	/* Kolor potokow FIFO */
#define SETUID "\x1B[48;5;196;38;5;15m"	/* Kolor plikow (u + s) */
#define SETGID "\x1B[48;5;11;38;5;16m" /* Kolor plikow (g + s) */
#define EXEC "\x1B[38;5;40m" /* Kolor plikow wykonywalnych */
#define RESET "\x1B[0m" /* Przywrocenie domyslnego koloru */

void getTotal (char **T_names, int num_of_el); /* Funkcja zliczajaca i wypisujaca ilosc zaalokowanych blokow pamieci */
void printFileType (char *name);  /* Funkcja wypisujaca typ pliku */
void printPermissions (char *name); /* Funkcja wypisujaca uprawnienia */
void printNodes (char *name, int width); /* Funkcja wypisujaca liczbe dowiazan */
void printUser (char *name, int width); /* Funkcja wypisujaca nazwe wlasciciela pliku */
void printGroup (char *name, int width); /* Funkcja wypisujaca grupe pliku */
void printSize (char *name, int width);	/* Funkcja wypisujaca rozmiar pliku */
void printDate (char *name); /* Funkcja wypisujaca date ostatniej modyfikacji */
void printFilename (char *name); /* Funkcja wypisujaca nazwy plikow wraz z kolorami */
int myCompare (const void *a, const void *b); /* Funkcja sluzaca w qsorcie do porownania stringow nazw plikow */
int numberOfElements (DIR *dir); /* Funkcja zliczajaca liczbe elementow w katalogu */
int nodeWidth (char **T_names, int num_of_el); /* Funkcja wyznaczajaca szerokosc na pole dowiazan */
int userWidth (char **T_names, int num_of_el); /* Funkcja wyznaczajaca szerokosc na pole wlasciciela */
int groupWidth (char **T_names, int num_of_el); /* Funkcja wyznaczajaca szerokosc na pole grupy */
int sizeWidth (char **T_names, int num_of_el); /*Funkcja wyznaczajaca szerokosc na pole rozmiaru pliku */
void ls (); /* Funkcja wypisujaca ls -la */
void printSize_Mode2 (char *name); /* Funkcja wypisujaca rozmiar pliku w trybie drugim */
void printBegining (char *name); /* Funkcja wypisujaca 80 pierwszych znakow zawartosci pliku */
void printDate_Mode2 (char *name, int date); /* Funkcja wypisujaca daty w trybie drugim
					       date - zawiera informacje ktora data ma zostac wypisana
					       0 - ostatniego uzycia
					       1 - ostatniej modyfikacji
					       2 - ostatniej zmiany stanu */
void mode2 (char *name); /* Funkcja wypisujaca informacje o danym pliku (tryb drugi) */

int main(int argc, char **argv)
{
	int i = 0;
	if (argc == 1)
	{
		ls();
	}
	else
	{
		for (i = 1; i < argc; i++)
		{
			mode2(argv[i]);
		}
	}
	return 0;
}

void getTotal (char **T_names, int num_of_el)
{
	long int total = 0;
	int i;
	struct stat statbuf;
	for (i = 0; i < num_of_el; i++)
	{
		if ((lstat (T_names[i], &statbuf)) == -1)
		{
			perror("BLAD LSTAT");
			exit(EXIT_FAILURE);
		}
		total += statbuf.st_blocks;
	}
	printf("total %ld\n", total/2);
}

void printFileType (char *name)
{
	struct stat statbuf;
	if ((lstat (name, &statbuf)) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	switch (statbuf.st_mode & S_IFMT)
	{
		case S_IFBLK: printf("b"); break;
		case S_IFCHR: printf("c"); break;
		case S_IFDIR: printf("d"); break;
		case S_IFIFO: printf("p"); break;
		case S_IFLNK: printf("l"); break;
		case S_IFREG: printf("-"); break;
		case S_IFSOCK: printf("s"); break;
	}
}

void printPermissions (char *name)
{
	struct stat statbuf;
	if ((lstat (name, &statbuf)) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	printf( (statbuf.st_mode &  S_IRUSR) ? "r" : "-");
	printf( (statbuf.st_mode &  S_IWUSR) ? "w" : "-");
	if (statbuf.st_mode & S_ISUID) 
		printf ("S");
	else 
		printf( (statbuf.st_mode &  S_IXUSR) ? "x" : "-");
	printf ( (statbuf.st_mode & S_IRGRP) ? "r" : "-");
	printf ( (statbuf.st_mode & S_IWGRP) ? "w" : "-");
	if (statbuf.st_mode & S_ISGID) 
		printf ("S");
	else 
		printf ( (statbuf.st_mode & S_IXGRP) ? "x" : "-");
	printf ( (statbuf.st_mode & S_IROTH) ? "r" : "-");
	printf ( (statbuf.st_mode & S_IWOTH) ? "w" : "-");
	printf ( (statbuf.st_mode & S_IXOTH) ? "x" : "-");
	printf (" ");
}

void printNodes (char *name, int width)
{
	struct stat statbuf;
	if ((lstat (name, &statbuf)) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	long int nodes = statbuf.st_nlink;
	printf ("%*ld ", width, nodes);
}

void printUser (char *name, int width)
{
	struct stat statbuf;
	struct passwd *owner;
	uid_t ownerid;
	if ((lstat (name, &statbuf)) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	ownerid = statbuf.st_uid;
	if ((owner = getpwuid(ownerid)) == NULL)
	{
		perror("BLAD GETPWUID");
		exit(EXIT_FAILURE);
	}
	printf ("%-*s ", width, owner -> pw_name);
}

void printGroup (char *name, int width)
{
	struct stat statbuf;
	struct group *group;
	gid_t groupid;
	if ((lstat (name, &statbuf)) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	groupid = statbuf.st_gid;
	if ((group = getgrgid(groupid)) == NULL)
	{
		perror("BLAD GETGRGID");
		exit(EXIT_FAILURE);
	}
	printf ("%-*s ", width, group -> gr_name);
}

void printSize (char *name, int width)
{
	struct stat statbuf;
	if ((lstat (name, &statbuf)) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	long long int size = statbuf.st_size;
	printf ("%*lld ", width, size);
}

void printDate (char *name)
{
	struct tm time;
	struct stat statbuf;
	char* month;
	if ((lstat (name, &statbuf)) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	time = * localtime_r(&statbuf.st_mtime, &time);
	switch (time.tm_mon)
	{
		case 0: month = "sty"; break;
		case 1: month = "lut"; break;
		case 2: month = "mar"; break;
		case 3: month = "kwi"; break;
		case 4: month = "maj"; break;
		case 5: month = "cze"; break;
		case 6: month = "lip"; break;
		case 7: month = "sie"; break;
		case 8: month = "wrz"; break;
		case 9: month = "paź"; break;
		case 10: month = "lis"; break;
		case 11: month = "gru"; break;
	}
	printf ("%*d %s ", 2, time.tm_mday, month);
	switch (time.tm_hour)
	{
		case 0: printf ("0"); break;
		case 1: printf ("0"); break;
		case 2: printf ("0"); break;
		case 3: printf ("0"); break;
		case 4: printf ("0"); break;
		case 5: printf ("0"); break;
		case 6: printf ("0"); break;
		case 7: printf ("0"); break;
		case 8: printf ("0"); break;
		case 9: printf ("0"); break;
	}
	printf ("%d:", time.tm_hour);
	switch (time.tm_min)
	{
		case 0: printf ("0"); break;
		case 1: printf ("0"); break;
		case 2: printf ("0"); break;
		case 3: printf ("0"); break;
		case 4: printf ("0"); break;
		case 5: printf ("0"); break;
		case 6: printf ("0"); break;
		case 7: printf ("0"); break;
		case 8: printf ("0"); break;
		case 9: printf ("0"); break;
	}
	printf ("%d ", time.tm_min);
}

void printFilename (char *name)
{
	int guardian = 1; /* Zmienna sprawdzajaca czy juz plik zostal pokolorowany */
	struct stat statbuf;
	char *buf;
	ssize_t nbytes, bufsiz;
	if (lstat(name, &statbuf) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	if ((statbuf.st_mode & S_IFMT) == S_IFLNK)
	{
		bufsiz = statbuf.st_size + 1;
		if ((buf = malloc(bufsiz)) == NULL)
		{
			perror("BLAD MALLOC");
			exit(EXIT_FAILURE);
		}
		if ((nbytes = readlink(name, buf, bufsiz)) == -1)
		{
			perror("BLAD READLINK");
			exit(EXIT_FAILURE);
		}
		buf[nbytes] = '\0';
		printf(LINK"%s"RESET" -> ", name);
		if (lstat(buf, &statbuf) == -1)
		{
			perror("BLAD LSTAT");
			exit(EXIT_FAILURE);
		}
		switch (statbuf.st_mode & S_IFMT)
		{
			case S_IFDIR: 
				printf(DIRECTORY); 
				guardian = 0; 
				break;
			case S_IFIFO: 
				printf(PIPE);
			        guardian = 0;	
			        break;
		}
		if (guardian == 1)
		{
			if (statbuf.st_mode & S_ISUID)
			{	
				printf(SETUID);
				guardian = 0;
			}
			else
				if (statbuf.st_mode & S_ISGID)
				{	
					printf(SETGID);
					guardian = 0;
				}
		}
		if (guardian == 1)
		{
			if (statbuf.st_mode & S_IXUSR)
				printf(EXEC);
			if (statbuf.st_mode & S_IXGRP)
				printf(EXEC);
			if (statbuf.st_mode & S_IXOTH)
				printf(EXEC);
		}
		printf("%.*s"RESET"\n", (int) nbytes, buf);
	}
	else
	{
		switch (statbuf.st_mode & S_IFMT)
		{
			case S_IFDIR: 
				printf(DIRECTORY); 
				guardian = 0; 
				break;
			case S_IFIFO: 
				printf(PIPE);
			        guardian = 0;	
			        break;
		}
		if (guardian == 1)
		{
			if (statbuf.st_mode & S_ISUID)
			{	
				printf(SETUID);
				guardian = 0;
			}
			else
				if (statbuf.st_mode & S_ISGID)
				{	
					printf(SETGID);
					guardian = 0;
				}
		}
		if (guardian == 1)
		{
			if (statbuf.st_mode & S_IXUSR)
				printf(EXEC);
			if (statbuf.st_mode & S_IXGRP)
				printf(EXEC);
			if (statbuf.st_mode & S_IXOTH)
				printf(EXEC);
		}
		printf("%s"RESET"\n", name);
	}
}

int numberOfElements(DIR *dir)
{
	int counter = 0; /* Licznik */
	struct dirent *dp;
	for (;;)
	{
		dp = readdir(dir);
		if (dp == NULL)
			break;
		counter++;
	}
	return counter;
}

int nodeWidth (char **T_names, int num_of_el)
{
	int width = 0, i, temp = 0, temp2 = 0; /* width - szukana szerokosc, temp - zmienna pomocnicza z 
						  iloscia dowiazan danego pliku, temp2 - zmienna pomocnicza 
						  zliczajaca ilosc cyfr w zapisie danej ilosci dowiazan */
	struct stat statbuf;
	for (i = 0; i < num_of_el; i++)
	{
		temp2 = 0;
		if (lstat(T_names[i], &statbuf) == -1)
		{
			perror("BLAD LSTAT");
			exit(EXIT_FAILURE);
		}
		temp = statbuf.st_nlink;
		while (temp != 0)
		{
			temp2++;
			temp = temp/10;
		}	
		if (width < temp2)
		{
			width = temp2;
		}
	}	
	return width;
}

int userWidth (char **T_names, int num_of_el)
{
	int width = 0, i; /* width - szukana szerokosc */
	struct stat statbuf;
	struct passwd *owner;
	uid_t ownerid;
	for (i = 0; i < num_of_el; i++)
	{
		if (lstat(T_names[i], &statbuf) == -1)
		{
			perror("BLAD LSTAT");
			exit(EXIT_FAILURE);
		}
		ownerid = statbuf.st_uid;
		if ((owner = getpwuid(ownerid)) == NULL)
		{
			perror("BLAD GETPWUID");
			exit(EXIT_FAILURE);
		}
		if (strlen(owner -> pw_name) > width)
		{
			width = strlen(owner -> pw_name);
		}
	}
	return width;
}

int groupWidth (char **T_names, int num_of_el)
{
	int width = 0, i; /* width - szukana szerokosc */
	struct stat statbuf;
	struct group *group;
	gid_t groupid;
	for (i = 0; i < num_of_el; i++)
	{
		if (lstat(T_names[i], &statbuf) == -1)
		{
			perror("BLAD LSTAT");
			exit(EXIT_FAILURE);
		}
		groupid = statbuf.st_gid;
		if ((group = getgrgid(groupid)) == NULL)
		{
			perror("BLAD GETGRGID");
			exit(EXIT_FAILURE);
		}
		if (strlen(group -> gr_name) > width)
		{
			width = strlen(group -> gr_name);
		}
	}
	return width;
}

int sizeWidth (char **T_names, int num_of_el)
{
	int width = 0, i, temp2 = 0; /* width - szukana szerokosc, temp2 - zmienna pomocnicza zliczajaca
       					ilosc cyfr w zapisie rozmiaru danego pliku */
	long long int temp = 0; /* zmienna pomocnicza przyjmujaca rozmiar danego pliku */
	struct stat statbuf;
	for (i = 0; i < num_of_el; i++)
	{
		temp2 = 0;
		if (lstat(T_names[i], &statbuf) == -1)
		{
			perror("BLAD LSTAT");
			exit(EXIT_FAILURE);
		}
		temp = statbuf.st_size;
		while (temp != 0)
		{
			temp2++;
			temp = temp/10;
		}	
		if (width < temp2)
		{
			width = temp2;
		}
	}	
	return width;
}

int myCompare (const void *a, const void *b)
{
	return strcasecmp( *(char * const *) a, *(char * const *) b );
}

void ls()
{
	DIR *dir;
	char **T_names; /* tablica przechowujaca nazwy plikow */
	struct dirent *dp;
	int num_of_el, i = 0, node_width, user_width, group_width, size_width; 
	/* num_of_el - zmienna przechowujaca liczbe elementow w katalogu,
	   node_width - szerokosc liczby dowiazan, 
	   user_width - szerokosc pola wlasciciela,
	   group_width - serokosc pola grupy
	   size_width - szerokosc pola rozmiaru pliku */
	if ((dir = opendir(".")) == NULL)
	{
		perror("OPEN DIR ERROR");
		exit(EXIT_FAILURE);
	}
	num_of_el = numberOfElements(dir);
	rewinddir(dir);	
	T_names = (char**) malloc(sizeof (char*) * num_of_el);
	for (i = 0; ; i++)
	{
		dp = readdir(dir);
		if (dp == NULL)
			break;
		T_names[i] = (char*) malloc(strlen(dp->d_name) + 1);
		strcpy(T_names[i], dp->d_name);
	}
	getTotal (T_names, num_of_el);
	qsort (T_names, num_of_el, sizeof (char*), myCompare);
	node_width = nodeWidth (T_names, num_of_el);
	user_width = userWidth (T_names, num_of_el);
	group_width = groupWidth (T_names, num_of_el);
	size_width = sizeWidth (T_names, num_of_el);
	for (i = 0; i < num_of_el; i++)
	{
		printFileType (T_names[i]);
		printPermissions (T_names[i]);
		printNodes (T_names[i], node_width);
		printUser (T_names[i], user_width);	
		printGroup (T_names[i], group_width);
		printSize (T_names[i], size_width);
		printDate (T_names[i]);
		printFilename (T_names[i]);
	}
	for (i = 0; i < num_of_el; i++)
	{
		free(T_names[i]);
	}
	free(T_names);
	closedir(dir);
}

void printSize_Mode2 (char *name)
{
	struct stat statbuf;
	if (lstat(name, &statbuf) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	printf ("Rozmiar:\t%lld ", (long long) statbuf.st_size);
	switch (statbuf.st_size)
	{
		case 1: printf("bajt\n"); break;
		case 2: printf("bajty\n"); break;
		case 3: printf("bajty\n"); break;
		case 4: printf("bajty\n"); break;
		default: printf("bajtow\n"); break;
	}
}

void printDate_Mode2 (char *name, int date) /* date - zawiera informacje ktory data ma zostac wypisana
					       0 - ostatniego uzycia
					       1 - ostatniej modyfikacji
					       2 - ostatniej zmiany stanu */
{
	struct tm time;
	struct stat statbuf;
	char* month;
	if (lstat(name, &statbuf) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	switch (date)
	{
		case 0: time = * localtime_r(&statbuf.st_atime, &time); break;
		case 1: time = * localtime_r(&statbuf.st_mtime, &time); break;
		case 2: time = * localtime_r(&statbuf.st_ctime, &time); break;
	}
	switch (time.tm_mon)
	{
		case 0: month = "stycznia"; break;
		case 1: month = "lutego"; break;
		case 2: month = "marca"; break;
		case 3: month = "kwietnia"; break;
		case 4: month = "maja"; break;
		case 5: month = "czerwca"; break;
		case 6: month = "lipca"; break;
		case 7: month = "sierpnia"; break;
		case 8: month = "wrzesnia"; break;
		case 9: month = "pazdziernika"; break;
		case 10: month = "listopada"; break;
		case 11: month = "grudnia"; break;
	}
	printf ("%*d %s %d roku o ", 2, time.tm_mday, month, time.tm_year + 1900);
	switch (time.tm_hour)
	{
		case 0: printf ("0"); break;
		case 1: printf ("0"); break;
		case 2: printf ("0"); break;
		case 3: printf ("0"); break;
		case 4: printf ("0"); break;
		case 5: printf ("0"); break;
		case 6: printf ("0"); break;
		case 7: printf ("0"); break;
		case 8: printf ("0"); break;
		case 9: printf ("0"); break;
	}
	printf ("%d:", time.tm_hour);
	switch (time.tm_min)
	{
		case 0: printf ("0"); break;
		case 1: printf ("0"); break;
		case 2: printf ("0"); break;
		case 3: printf ("0"); break;
		case 4: printf ("0"); break;
		case 5: printf ("0"); break;
		case 6: printf ("0"); break;
		case 7: printf ("0"); break;
		case 8: printf ("0"); break;
		case 9: printf ("0"); break;
	}
	printf ("%d:", time.tm_min);
	switch (time.tm_sec)
	{
		case 0: printf ("0"); break;
		case 1: printf ("0"); break;
		case 2: printf ("0"); break;
		case 3: printf ("0"); break;
		case 4: printf ("0"); break;
		case 5: printf ("0"); break;
		case 6: printf ("0"); break;
		case 7: printf ("0"); break;
		case 8: printf ("0"); break;
		case 9: printf ("0"); break;
	}
	printf ("%d", time.tm_sec);
}

void printBegining (char *name)
{
	int file, n;
	char bufor[100];
	if ((file = open(name, O_RDONLY)) == -1)
	{
		perror("BLAD OTWARCIA PLIKU");
		exit(EXIT_FAILURE);
	}
	n = read(file, bufor, 80);
	bufor[n] = '\0';
	printf("%s", bufor);
	close(file);
}

void mode2 (char *name)
{
	struct stat statbuf;
	char *buf;
	ssize_t bufsiz;
	printf ("Informacje o %s:\n", name);
	printf ("Typ pliku:\t");
	if (lstat(name, &statbuf) == -1)
	{
		perror("BLAD LSTAT");
		exit(EXIT_FAILURE);
	}
	switch (statbuf.st_mode & S_IFMT)
	{
		case S_IFDIR: printf("katalog\n"); break;
		case S_IFIFO: printf("potok FIFO\n"); break;
		case S_IFLNK: printf("link symboliczny\n"); break;
		case S_IFREG: printf("zwykly plik\n"); break;
	}
	printf ("Sciezka:\t%s/%s\n", getenv("PWD"), name);
	if ((statbuf.st_mode & S_IFMT) == S_IFLNK)
	{
		bufsiz = statbuf.st_size + 1;
		buf = malloc(bufsiz);
		if (buf == NULL)
		{
			perror("MALOC ERROR");
			exit(EXIT_FAILURE);
		}
		if ((realpath(name, buf)) == NULL)
		{
			perror("BLAD REALPATH");
			exit(EXIT_FAILURE);
		}
		printf ("Wskazuje na:\t%s\n", buf );	
	}
	printSize_Mode2 (name);	
	printf ("Uprawnienia:\t");
	printPermissions (name);
	printf ("\nOstatnio uzywany:\t ");
	printDate_Mode2 (name, 0);
	printf ("\nOstatnio modyfikowany:\t ");
	printDate_Mode2 (name, 1);
	printf ("\nOstatnio zmieniany stan: ");
	printDate_Mode2 (name, 2);
	printf ("\n");
	if ((statbuf.st_mode & S_IFMT) == S_IFREG)
	{
		
		if (!(statbuf.st_mode & S_IXUSR))
		{
			if (!(statbuf.st_mode & S_IXGRP))
			{
				if (!(statbuf.st_mode & S_IXOTH))
				{
					printf ("Poczatek zawartosci:\n");
					printBegining (name);
					printf("\n");
				}
			}
		}	
	}
}
