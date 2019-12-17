#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>

/* stworzenie i nasluchiwanie na gniezdzie */
int listen_socket(int listen_port)
{
  struct sockaddr_in addr;
  int socket_descriptor;

  /* stworzenie gniazda */
  if ((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    perror("blad socket");
    exit(EXIT_FAILURE);
  }

  /* ustawienie gniazda w tryb nieblokujacy */
  int val;
  if ((val = fcntl(socket_descriptor, F_GETFL, 0)) == -1)
  {
    perror("blad fcntl");
    exit(EXIT_FAILURE);
  }
  if (fcntl(socket_descriptor, F_GETFL, val | O_NONBLOCK) == -1)
  {
    perror("blad fcntl");
    exit(EXIT_FAILURE);
  }

  /* ustawienie by dalo sie uzywac danego portu wielokrotnie */
  int yes = 1;
  if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
  {
    perror("blad setsockopt");
    exit(EXIT_FAILURE);
  }

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(listen_port);

  /* bindowanie gniazda */
  if (bind(socket_descriptor, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("blad bind");
    exit(EXIT_FAILURE);
  }

  /* nasluchiwanie gniazda */
  if (listen(socket_descriptor, SOMAXCONN) == -1)
  {
    perror("blad listen");
    exit(EXIT_FAILURE);
  }
  return socket_descriptor;
}

int main(int argc, char const **argv)
{
  int listen_socket_descriptor[argc - 1]; /* tablica deskryptorow nasluchujacych */
  int local_port[argc - 1];               /* tablica portow serwera */
  char host_port[argc - 1][100];          /* tablica portow clienta */
  char host[argc - 1][100];               /* tablica adressow clienta */

  /* inicjalizacja struktury do poll'a */
  int nfds = argc - 1;
  struct pollfd *fds = malloc(sizeof(struct pollfd) * nfds);
  int timeout = 120 * 1000; /* timeout ustawiony na 2 minuty */

  struct addrinfo *client_info[argc - 1]; /* tablica zawierajaca informacje o klientach */
  for (int i = 0; i < argc - 1; i++)
  {
    sscanf(argv[i + 1], "%d:%[^:]:%s", &local_port[i], host[i], host_port[i]);

    /* pobranie informacji o kliencie */
    if (getaddrinfo(host[i], host_port[i], NULL, &client_info[i]) < 0)
    {
      printf("blad getaddrinfo");
      exit(EXIT_FAILURE);
    }
    listen_socket_descriptor[i] = listen_socket(local_port[i]);

    /* ustawienie poczatkowych gniazd nasluchu */
    fds[i].fd = listen_socket_descriptor[i];
    fds[i].events = POLLIN | POLLPRI | POLLRDHUP;
  }
  int poll_val;

  /* petla czekajaca na polaczenia lub dane na dowolnym z podlaczonych gniazd */
  while (1)
  {
    /* wywolanie poll'a */
    /* -1 - pojawil sie blad */
    /* 0 - osiagnieto limit czasu (timeout) */
    /* >0 - liczba gotowych deskryptorow do dzialania */
    if ((poll_val = poll(fds, nfds, timeout)) < 0)
    {
      perror("blad poll");
      exit(EXIT_FAILURE);
    }
    if (poll_val == 0)
    {
      printf("Timeout\n");
      exit(EXIT_FAILURE);
    }
    /* 1 albo wiecej deskryptorow sa "readable", wiec musimy zlokalizowac ktore */
    /* przeprowadzamy petle w celu znalezienia tych ktore zwrocily POLLIN */
    /* i ustalamy czy sa nasluchujacymi czy aktywnymi polaczeniami */
    for (int i = 0; i < nfds; i++)
    {
      /* ignorujemy ujemne deskryptory (ktore zwracaja w revents wlasnie 0) */
      if (fds[i].revents == 0)
      {
        continue;
      }
      /* znaleziono POLLIN, lub POLLPRI, czyli sa jakies dane */
      if (((fds[i].revents & POLLIN) == POLLIN) || ((fds[i].revents & POLLPRI) == POLLPRI))
      {
        /* jezeli nasluchujacy to storz nowe polaczenie */
        if (fds[i].fd == listen_socket_descriptor[i])
        {
          struct sockaddr_in client_address;
          bzero(&client_address, sizeof(client_address));
          socklen_t client_address_size = sizeof(client_address);
          /* dodaje 2 miejsca do tablicy poll'a, pierwsze na accept, drugie na connect */
          fds = realloc(fds, sizeof(struct pollfd) * (nfds + 2));
          fds[nfds].events = POLLIN | POLLPRI | POLLRDHUP;
          fds[nfds + 1].events = POLLIN | POLLPRI | POLLRDHUP;
          /* wywolanie accept */
          if ((fds[nfds].fd = accept(listen_socket_descriptor[i], (struct sockaddr *)&client_address, &client_address_size)) < 0)
          {
            perror("blad accept");
            exit(EXIT_FAILURE);
          }
          /* gniazdo do wykorzystania w connect */
          if ((fds[nfds + 1].fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
          {
            perror("blad socket");
            exit(EXIT_FAILURE);
          }
          /* iteracja po zwroconych adresach */
          for (struct addrinfo *tmp = client_info[i]; tmp != NULL; tmp = tmp->ai_next)
          {
            /*wywolanie connect*/
            if (connect(fds[nfds + 1].fd, tmp->ai_addr, tmp->ai_addrlen) == -1)
            {
              continue;
            }
            /* przerwij po znaleznieniu pierwszego poprawnego adresu */
            break;
          }
          /* ustawienie gniazda w tryb nieblokujacy */
          int val;
          if ((val = fcntl(fds[nfds + 1].fd, F_GETFL, 0)) == -1)
          {
            perror("blad fcntl");
            exit(EXIT_FAILURE);
          }
          if (fcntl(fds[nfds + 1].fd, F_GETFL, val | O_NONBLOCK) == -1)
          {
            perror("blad fcntl");
            exit(EXIT_FAILURE);
          }
          nfds += 2;
        }
        else /* sa dane do odebrania (istniejace polaczenie musi byc "readable") */
        {
          char buffer[1024];
          int nbytes;
          if ((argc - 1) % 2 ? (i % 2) : ((i + 1) % 2)) /* 1 - odbieramy z accept i wysylamy do connect */
          {
            /* odbieramy dane z accept */
            if ((nbytes = recv(fds[i].fd, buffer, 1024, 0)) == -1)
            {
              perror("blad recv");
              exit(EXIT_FAILURE);
            }
            buffer[nbytes] = '\0';
            /* wysylamy dane do connect */
            send(fds[i + 1].fd, buffer, nbytes, 0);
          }
          else /* 0 - odbieramy z connect i wysylamy do accept */
          {
            /* odbieramy dane z connect */
            if ((nbytes = recv(fds[i].fd, buffer, 1024, 0)) == -1)
            {
              perror("blad recv");
              exit(EXIT_FAILURE);
            }
            buffer[nbytes] = '\0';
            /* wysylamy dane do accept */
            send(fds[i - 1].fd, buffer, nbytes, 0);
          }
        }
      }
      /* gniazdo zakonczylo komunikacje */
      if ((fds[i].revents & POLLRDHUP) == POLLRDHUP)
      {
        if ((argc - 1) % 2 ? (i % 2) : ((i + 1) % 2))
        {
          close(fds[i].fd);
          close(fds[i + 1].fd);
          fds[i].fd = -fds[i].fd;
          fds[i + 1].fd = -fds[i + 1].fd;
        }
        else
        {
          close(fds[i].fd);
          close(fds[i - 1].fd);
          fds[i].fd = -fds[i].fd;
          fds[i - 1].fd = -fds[i - 1].fd;
        }
      }
    }
  }
  return 0;
}