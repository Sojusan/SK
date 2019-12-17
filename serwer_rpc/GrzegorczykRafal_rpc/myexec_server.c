/*
 * This is sample code generated by rpcgen.
 * These are only templates and you can use them
 * as a guideline for developing your own functions.
 */

#include "myexec.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>

data_out *
myexec_1_svc(data_in *argp, struct svc_req *rqstp)
{
  static data_out result;
  char buffer[2048];              /* bufor na output exec'a */
  char text[1000];                /* wiadomosc przeslana przy interaktywnych */
  bzero(&buffer, sizeof(buffer)); /* zerowanie bufora */
  int pipe_out[2];                /* potok wyjscia (przekierowanie STDOUT) */
  int pipe_in[2];                 /* potok wejscia (przekierowanie STDIN) */
  int pipe_err[2];                /* potok awarii (przekierowanie STDERR) */
  /* inicjalizacja potokow */
  pipe(pipe_out);
  pipe(pipe_in);
  pipe(pipe_err);

  char *arguments_table[100]; /* tablica argumentow potrzebna przy execvp */
  arguments_table[0] = argp->command;
  /* zmienne pomocnicze */
  /* j - kolejny znak z argp->argument */
  /* k - ktory element z arguments_table */
  /* l - kolejne znaki w tablicy pomocniczej sign_table */
  int j = 0, k = 1, l = 0;
  int interactive = 0; /* informacja czy ma byc interaktywnie */
  char sign;           /* zmienna przechowujaca kolejne znaki z argp->argument */
  /* tablica scalajaca sign w argumenty */
  /* potrzebna jest gdyz arguments_table sa wskaznikami */
  /* i musza wskazywac na istniejace elementy */
  char sign_table[100][100];
  if (strcmp(argp->argument, "") == 0) /* jezeli brak argumentow */
  {
    arguments_table[0] = argp->command;
    arguments_table[1] = NULL;
  }
  else /* argumenty wystapily */
  {
    do /* wypelniam arguments_table */
    {
      sign = argp->argument[j];
      /* rozdzielam argumenty */
      if (sign != ' ' && sign != '\n' && sign != '\0')
      {
        sign_table[k][l++] = sign;
      }
      else
      {
        /* sprawdzam czy ma byc interaktywnie */
        if (strcmp(sign_table[k], "-i+") == 0)
        {
          interactive = 1;
          strcpy(sign_table[k], "");
          l = 0;
        }
        else
        {
          arguments_table[k] = sign_table[k];
          k++;
          l = 0;
        }
      }
      j++;
    } while (sign != '\0');
    arguments_table[k] = NULL;
  }

  /* wypisyanie komendy oraz argumentow */
  printf("Command: %s\n", argp->command);
  if (interactive == 1)
  {
    /* wypisanie argumentow bez inforamcji o trybie interaktywnym */
    printf("Argument: %s\n", argp->argument + 4);
  }
  else
  {
    printf("Argument: %s\n", argp->argument);
  }

  if (interactive == 1)
  {
    /* kopiuje wiadomosc */
    strcpy(text, argp->argument + 4);
    strcat(text, "\n");

    pid_t child;
    if ((child = fork()) == 0)
    {
      /* ustawiam odpowiednio przekierowanie deskryptorow */
      dup2(pipe_out[1], STDOUT_FILENO);
      dup2(pipe_in[0], STDIN_FILENO);
      dup2(pipe_err[1], STDERR_FILENO);
      execlp(argp->command, argp->command, (char *)NULL);
    }
    else
    {
      /* wysylam wiadomosc do exec'a */
      write(pipe_in[1], text, sizeof(text));
      /* czytam wiadomosc zwrocona przez exec'a */
      int nbytes = read(pipe_out[0], buffer, sizeof(buffer));
      if (nbytes == 0)
      {
        int errbytes = read(pipe_err[0], buffer, sizeof(buffer));
      }
      /* koncze cat */
      kill(child, SIGINT);
      wait(NULL);
    }
  }
  else /* nie interaktywne */
  {
    if (fork() == 0)
    {
      dup2(pipe_out[1], STDOUT_FILENO);
      dup2(pipe_err[1], STDERR_FILENO);
      close(pipe_out[0]);
      close(pipe_out[1]);
      close(pipe_err[0]);
      close(pipe_err[1]);
      execvp(argp->command, arguments_table);
    }
    else
    {
      close(pipe_out[1]);
      close(pipe_err[1]);
      int nbytes = read(pipe_out[0], buffer, sizeof(buffer));
      if (nbytes == 0)
      {
        int errbytes = read(pipe_err[0], buffer, sizeof(buffer));
      }
      wait(NULL);
    }
  }
  memcpy(&result, buffer, sizeof(buffer)); /* uzupelniam result */
  printf("Result:\n%s\n", result.data_out);
  bzero(&sign_table, sizeof(sign_table)); /* zerowanie tablicy pomocniczej z argumentami */
  return &result;
}

/*
Przetestowane:
ls
ls -laRi
cat
cat <plik>
ps
ps -a
touch plik.txt
touch plik1.txt plik2.txt ... plikn.txt
rm plik.txt
rm plik1.txt plik2.txt ... plikn.txt
echo <tekst>
*/