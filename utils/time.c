#include <stdio.h>
#include <time.h>

int print_time(int start_end) {
  time_t rawtime;
  struct tm * timeinfo;
  char buffer [80];

  time (&rawtime);
  timeinfo = localtime (&rawtime);

  strftime (buffer, 80, "%T",timeinfo);
  fprintf(stderr, "%s time: %s\n", (start_end == 0) ? "Start" : "End" ,buffer);

  return 0;
}
