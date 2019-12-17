#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>

#define MSG_MAX_SIZE 1024

#define SERVER "\x1B[38;5;46m"  /* kolor nazwy serwera */
#define CLIENT "\x1B[38;5;220m" /* kolor nazwy klienta */
#define END "\x1B[38;5;196m"    /* kolor napisu "<koniec>" */
#define IP "\x1B[38;5;135m"     /* kolor adresu IP */
#define RESET "\x1B[0m"         /* przywrocenie domyslnego koloru */

/* struktura przechowujaca informacje */
struct my_msg
{
  char name[100];
  char text[MSG_MAX_SIZE];
};

int main(int argc, char *argv[])
{
  if (argc < 2 || argc > 3)
  {
    printf("Uzycie: %s host [nazwa_uzytkownika]\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  int sockfd;                                  /* gniazdo */
  struct sockaddr_in server_addr, client_addr; /* struktura dla serwera i dla klienta */
  u_short my_port = 19901;                     /* wybrany port */
  struct my_msg msg;                           /* struktura z wiadomoscia do przesylania */
  socklen_t client_length;                     /* rozmiar dla klienta potrzebny w recvfrom */
  char nickname[100];                          /* nick uzytkownika */
  /* sigaction do obslugi sygnalow */
  struct sigaction sigtstp, sigint;
  /* ignoruje sygnaly aby uzytkownik musial wpisac <koniec> */
  sigtstp.sa_handler = SIG_IGN;
  sigint.sa_handler = SIG_IGN;
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
  /* zeruje struktury */
  memset(&server_addr, 0, sizeof(server_addr));
  memset(&client_addr, 0, sizeof(client_addr));
  /* jezeli jest nick to go podstawiam */
  if (argc == 3)
  {
    strcpy(msg.name, argv[2]);
    strcpy(nickname, argv[2]);
  }
  else
  {
    strcpy(msg.name, "NN");
    strcpy(nickname, "NN");
  }
  /* tworze gniazdo */
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
  {
    perror("Blad tworzenia gniazda.");
    exit(EXIT_FAILURE);
  }
  /* pobranie informacji o kliencie*/
  struct hostent *host;
  if ((host = gethostbyname(argv[1])) == NULL)
  {
    herror("Blad z adresem lub nazwa domenowa (gethostbyname)");
    exit(EXIT_FAILURE);
  }
  /* podstawiam adres ip klienta do zmiennej client_ip */
  void *inaddr;
  inaddr = host->h_addr_list[0];
  char client_ip[INET6_ADDRSTRLEN];
  if (inet_ntop(host->h_addrtype, inaddr, client_ip, sizeof(client_ip)) == NULL)
  {
    perror("Blad z adresem (inet_ntop)");
    exit(EXIT_FAILURE);
  }
  /* uzupelniam strukture */
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(my_port);
  /* binduje gniazdo */
  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
  {
    perror("Blad bindowania gniazda.");
    exit(EXIT_FAILURE);
  }
  printf("Rozpoczynam czat z" IP " %s" RESET ". Napisz " END "<koniec>" RESET " by zakonczyc czat.\n", client_ip);
  int pid; /* numer pid dla forka */
  if ((pid = fork()) == 0)
  {
    /* server */
    int new_person = 0;                  /* zmienna pomocnicza do informowania, czy polaczyl sie uzytkownik */
    client_length = sizeof(client_addr); /* pobieram rozmiar klienta */
    while (1)
    {
      /* odbieram wiadomosci */
      if (recvfrom(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)&client_addr, &client_length) == -1)
      {
        perror("Blad podczas odbierania wiadomosci.");
        exit(EXIT_FAILURE);
      }
      /* jezeli pojawil sie komunikat <start> oraz jeszcze zaden klient nie jest podlaczony */
      if ((strcmp(msg.text, "<start>") == 0) && (new_person == 0))
      {
        printf("\n[" CLIENT "%s" RESET " (" IP "%s" RESET ") dolaczyl do rozmowy]\n", msg.name, inet_ntoa(client_addr.sin_addr));
        printf("[" SERVER "%s" RESET "]> ", nickname);
        fflush(stdout);
        new_person = 1;
        continue;
      }
      /* jezeli pojawil sie komunikat <koniec> */
      if (strcmp(msg.text, "<koniec>") == 0)
      {
        printf("\n[" CLIENT "%s" RESET " (" IP "%s" RESET ") zakonczyl rozmowe].\n", msg.name, inet_ntoa(client_addr.sin_addr));
        printf("[" SERVER "%s" RESET "]> ", nickname);
        fflush(stdout);
        new_person = 0;
        continue;
      }
      /* wypisanie wiadomosci */
      printf("\n[" CLIENT "%s" RESET " (" IP "%s" RESET ")]> %s\n", msg.name, inet_ntoa(client_addr.sin_addr), msg.text);
      printf("[" SERVER "%s" RESET "]> ", nickname);
      fflush(stdout);
    }
  }
  else
  {
    /* klient */
    /* uzupelniam strukture */
    client_addr.sin_family = AF_INET;
    /* podstawiam ip klienta do struktury */
    bcopy((char *)host->h_addr_list[0], (char *)&client_addr.sin_addr, host->h_length);
    client_addr.sin_port = htons(my_port);
    /* wysylam wiadomosc o rozpoczeciu komunikacji */
    strcpy(msg.text, "<start>");
    if (sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1)
    {
      perror("Blad podczas wysylania wiadomosci.");
      exit(EXIT_FAILURE);
    }
    while (1)
    {
      /* pobieram wiadomosc dla serwera */
      printf("[" SERVER "%s" RESET "]> ", nickname);
      fgets(msg.text, MSG_MAX_SIZE, stdin);
      msg.text[strlen(msg.text) - 1] = '\0';
      /* wysylam wiadomosc */
      if (sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1)
      {
        perror("Blad podczas wysylania wiadomosci.");
        exit(EXIT_FAILURE);
      }
      /* jezeli <koniec> to koncze proces serwera */
      if (strcmp(msg.text, "<koniec>") == 0)
      {
        kill(pid, SIGKILL);
        break;
      }
    }
  }
  close(sockfd);
  return 0;
}