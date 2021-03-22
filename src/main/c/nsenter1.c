// based on https://github.com/justincormack/nsenter1/blob/eeb60b727f98f78a56a81e048fe938e1297980a5/nsenter1.c
/**
Copyright (C) 2016 Justin Cormack

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
*/

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

extern char **environ;

// Reassociate with the most important namespaces of pid 1

int main(int argc, char **argv) {
	char *shell = "/bin/sh";
	char *def[] = {shell, NULL};
	char *cmd = shell;
	char **args = def;
	int fdm = open("/proc/1/ns/mnt", O_RDONLY);
	int fdu = open("/proc/1/ns/uts", O_RDONLY);
	int fdn = open("/proc/1/ns/net", O_RDONLY);
	int fdi = open("/proc/1/ns/ipc", O_RDONLY);
	int froot = open("/proc/1/root", O_RDONLY);

	if (fdm == -1 || fdu == -1 || fdn == -1 || fdi == -1 || froot == -1) {
		fprintf(stderr, "Failed to open /proc/1 files, are you root?\n");
		exit(1);
	}

	if (setns(fdm, 0) == -1) {
		perror("setns:mnt");
		exit(1);
	}
	if (setns(fdu, 0) == -1) {
		perror("setns:uts");
		exit(1);
	}
	if (setns(fdn, 0) == -1) {
		perror("setns:net");
		exit(1);
	}
	if (setns(fdi, 0) == -1) {
		perror("setns:ipc");
		exit(1);
	}
	if (fchdir(froot) == -1) {
		perror("fchdir");
		exit(1);
	}
	if (chroot(".") == -1) {
		perror("chroot");
		exit(1);
	}
	if (argc > 1) {
		cmd = argv[1];
		args = argv + 1;
	}
	if (execvpe(cmd, args, environ) == -1) {
		perror("execvpe");
		exit(1);
	}
	exit(0);	
}
