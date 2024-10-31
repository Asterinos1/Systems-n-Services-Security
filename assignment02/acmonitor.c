#define MD5_HASH 33

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct access {
   int data;
   int key;
   struct access *accnext;
} ;

struct access *acchead = NULL;
struct access *acccurrent = NULL;

//display the list
void printAccessList() {
   struct access *ptr = acchead;
   printf("List of accesses:\n");
	
   //start from the beginning
   while(ptr != NULL) {
      printf("User ID: %d | Times: %d\n",ptr->key,ptr->data);
      ptr = ptr->accnext;
   }

}

//insert link at the first location
void insertAccessFirst(int key, int data) {
   //create a link
   struct access *link = (struct access*) malloc(sizeof(struct access));
	
   link->key = key;
   link->data = data;
	
   //point it to old first node
   link->accnext = acchead;
	
   //point first to new first node
   acchead = link;
}

//find a link with given key
struct access* findAccess(int key) {

   //start from the first link
   struct access* acccurrent = acchead;

   //if list is empty
   if(acchead == NULL) {
      return NULL;
   }

   //navigate through list
   while(acccurrent->key != key) {
	
      //if it is last node
      if(acccurrent->accnext == NULL) {
         return NULL;
      } else {
         //go to next link
         acccurrent = acccurrent->accnext;
      }
   }      
	
   //if data found, return the current Link
   return acccurrent;
}

//delete a link with given key
struct access* deleteAccess(int key) {

   //start from the first link
   struct access* acccurrent = acchead;
   struct access* accprevious = NULL;
	
   //if list is empty
   if(acchead == NULL) {
      return NULL;
   }

   //navigate through list
   while(acccurrent->key != key) {

      //if it is last node
      if(acccurrent->accnext == NULL) {
         return NULL;
      } else {
         //store reference to current link
         accprevious = acccurrent;
         //move to next link
         acccurrent = acccurrent->accnext;
      }
   }

   //found a match, update the link
   if(acccurrent == acchead) {
      //change first to point to next link
      acchead = acchead->accnext;
   } else {
      //bypass the current link
      accprevious->accnext = acccurrent->accnext;
   }    
	
   return acccurrent;
}
/*----------------------------------------------*/

/* Linked list that contains potential malicious users */
struct node {
   int data;
   int key;
   char files[8][FILENAME_MAX];
   struct node *next;
};

struct node *head = NULL;
struct node *current = NULL;


//display the list
void printList() {
   	struct node *ptr = head;
	printf("Malicious Users:\n");
	//start from the beginning
	while(ptr != NULL) {
		if (ptr->data>7)
			printf("%d\n",ptr->key);
		ptr = ptr->next;
	}
	// while(ptr != NULL) {
	// 	printf("%d %d", ptr->key, ptr -> data);
	// 	for (int i=0; i<8; i++)
	// 		 printf(" %s ",ptr->files[i]);
	// 	printf("\n");
	// 	ptr = ptr->next;
	// }
}

//delete a link with given key
struct node* delete_node(int key) {

   //start from the first link
   struct node* current = head;
   struct node* previous = NULL;
	
   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while(current->key != key) {

      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //store reference to current link
         previous = current;
         //move to next link
         current = current->next;
      }
   }

   //found a match, update the link
   if(current == head) {
      //change first to point to next link
      head = head->next;
   } else {
      //bypass the current link
      previous->next = current->next;
   }    
	
   return current;
}

//insert link at the first location
void insertFirst(int key, int data, char *file) {
	//create a link
	struct node *link = (struct node*) malloc(sizeof(struct node));

	link->key = key;
	link->data = data;
	memcpy(link->files[0], file, FILENAME_MAX);
	// for (int i=1; i<8; i++)
	// 	strcpy(link->files[i],"null");

	//point it to old first node
	link->next = head;

	//point first to new first node
	head = link;
}

//insert link at the first location
void insertList(int key, int data, char *file) {
	//create a link
	struct node *link = (struct node*) malloc(sizeof(struct node));
	
	// for (int i=0; i<8; i++) {
	// 	if (strcmp(file, link->files[i])){
	// 		printf("%s :: %s\n", file, link->files[i]);	
	// 		printf("File Exists\n");
	// 		file_exists = 1;
	// 		break;
	// 	}
	// 	else 
	// 		file_exists = 0;
	// }
	if (data<9) {
		link = delete_node(key);
		
		link->key = key;
		link->data = data;
		memcpy(link->files[data], file, FILENAME_MAX);

		//point it to old first node
		link->next = head;

		//point first to new first node
		head = link;
	}

}

//find a link with given key
struct node* find(int key) {

   //start from the first link
   struct node* current = head;

   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while(current->key != key) {
	
      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //go to next link
         current = current->next;
      }
   }      
	
   //if data found, return the current Link
   return current;
}


struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{

	/* add your code here */
	/* Get number of lines on the file */
	// int nlines;
	// char c; 

	// for (c = getc(log); c != EOF; c = getc(log)) 
    //     if (c == '\n') // Increment count if this character is newline 
    //         nlines++; 

	/* Read file line by line */
    char * line = NULL;
	char path[0xFFF];
    size_t len = 0;
    ssize_t read;
	int uid, is_action_denied, denied_times, file_in_list;
	file_in_list = 0;

    if (log == NULL)
        exit(EXIT_FAILURE);
	
    while ((read = getline(&line, &len, log)) != -1) {
        // printf("%s", line);
		/* Split line and get uid and action-denied-flag */
		uid = atoi(strtok(line, " ")); 
		memcpy(path, strtok(NULL, " "), FILENAME_MAX);
		for (int i=1; i<7; i++)
			strtok(NULL, " "); // We don't care for these elements
		is_action_denied = atoi(strtok(NULL, " "));
		/* Check if uid is already on the list */
		if (is_action_denied==1) {
			struct node *foundLink = find(uid);
			if (foundLink == NULL) {
				denied_times = 1;
				insertFirst(uid, denied_times, path); // Insert uid with 1 denied time
			}
			else {
				denied_times = foundLink -> data; // Save current denied times
				for (int i=0; i<8; i++) {
					// if (foundLink->files[i]) {
					// 	printf(foundLink->files[i]);
					// }
					if(strcmp(foundLink -> files[i], " ") && !strcmp(path, foundLink -> files[i])){
						// printf("%s :: %s\n", path, foundLink->files[i]);
						file_in_list = 1;
					}
				}
				if (file_in_list == 0)
					insertList(uid, denied_times + 1, path); // Insert Element with updated denied times
					// printf("%d %d %s\n", uid, denied_times, path);
			}
		}
    }

	printList();

    if (line)
        free(line);

	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	char * line , *file_name= NULL;
	char hash[MD5_HASH];
	char prev_hash[MD5_HASH];
	char path[0xFFF];
    size_t len = 0;
    ssize_t read;
	int uid, is_action_denied, accessed, file_mode;

    if (log == NULL)
        exit(EXIT_FAILURE);
	
    while ((read = getline(&line, &len, log)) != -1) {
        // printf("%s", line);
		/* Split line and get uid and action-denied-flag */
		uid = atoi(strtok(line, " ")); 
		memcpy(path, strtok(NULL, " "), FILENAME_MAX);
		for (int i=1; i<6; i++)
			strtok(NULL, " "); // We don't care for these elements
		file_mode = atoi(strtok(NULL, " "));
		is_action_denied = atoi(strtok(NULL, " "));
		memcpy(hash, strtok(NULL, " "), MD5_HASH);
		/* If hash is changed and is_action_denied == 0 */
		if (strncmp(hash, prev_hash,MD5_HASH) && file_mode == 3 && !is_action_denied && !strcmp(file_to_scan,path)) {
			memcpy(prev_hash, hash, MD5_HASH);
			/* Add to users list */
			struct node *foundLink = findAccess(uid);
			if (foundLink == NULL) {
				accessed = 1;
				insertAccessFirst(uid, accessed); // Insert uid with 1 denied time
			}
			else {
				accessed = foundLink -> data; // Save current denied times
				deleteAccess(uid); // Delete Older Access
				insertAccessFirst(uid, accessed + 1); // Insert Element with updated denied times
			}
		}
    }

	// printAccessList();
	printAccessList();

    if (line)
        free(line);

	return;


}




int main(int argc, char *argv[]){
	int ch;
	FILE *log;

	if (argc < 2)
		usage();
	
	log = fopen("file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
