extern int OpenConfigFile(void);
extern int QueryServers(char *, char *);
extern void Checktimer(void);
extern void Check_forchange(int);
extern int Read_denyusers(void);
extern int Read_allowusers(void);
extern int Check_user(char *);
extern int QueryServers(char *, char *);
extern int Check_ifuserallowed(char *ConnectingUser);
extern void Check_forallowchange(void);

