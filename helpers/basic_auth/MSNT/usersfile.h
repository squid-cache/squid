
typedef struct {
    char *path;
    char **names;
    int Alloc;
    int Inuse;
    time_t LMT;
} usersfile;

int Read_usersfile(const char *path, usersfile * uf);
int Check_userlist(usersfile * uf, char *User);
void Check_forfilechange(usersfile * uf);
