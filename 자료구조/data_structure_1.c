#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct node
{
    char data;
    struct node* next;
    struct node* prev;
}node;

typedef struct _list 
{
    node* head;
    node* tail;
    int size;
}list;

void setting(list* result_list);
void add(list* result_list, int position, char data);
void delete(list* result_list, int position);
void get(list* result_list, int position);

int main()
{
    int n;
    char character;
    int position;
    char data;

    list* a;
    a = (list*)malloc(sizeof(list));
    setting(a);

    scanf("%d", &n);
    getchar();

    for (int i = 0; i < n; i++) {
        scanf("%c", &character);

        if (character == 'A') 
        {
            scanf("%d %c", &position, &data);
            getchar();
            add(a, position, data);
        }
        else if (character == 'D')
        {
            scanf("%d", &position);
            getchar();
            delete(a, position);
        }
        else if (character == 'G')
        {
            scanf("%d", &position);
            getchar();
            get(a, position);
        }
        else if (character == 'P')
        {
            print(a);
            getchar();
        }

    }


    return 0;
}

void setting(list* result_list)
{
    node* newhead, * newtail;
    newhead = (node*)malloc(sizeof(node));
    newtail = (node*)malloc(sizeof(node));

    result_list->head = newhead;
    newhead->prev = NULL;
    newhead->next = newtail;

    result_list->tail = newtail;
    newtail->prev = newhead;
    newtail->next = NULL;

    result_list->size = 2;
}

void add(list* result_list, int position, char data)
{
    if ((result_list->size) - 1 < position)
    {
        printf("invalid position\n");
        return;
    }

    node* temp;
    temp = result_list->head;

    node* newnode;
    newnode = (node*)malloc(sizeof(node));

    newnode->data = data;

    for (int i = 0; i < position; i++)
        temp = temp->next;

    newnode->next = temp;
    newnode->prev = temp->prev;

    temp->prev = newnode;
    temp = newnode->prev;
    temp->next = newnode;

    result_list->size++;
}

void delete(list* result_list, int position)
{

    if ((result_list->size) - 2 < position)
    {
        printf("invalid position\n");
        return;
    }

    node* temp, * prev_temp, * next_temp;
    temp = result_list->head;

    for (int i = 0; i < position; i++)
        temp = temp->next;

    prev_temp = temp->prev;
    next_temp = temp->next;

    prev_temp->next = next_temp;
    next_temp->prev = prev_temp;

    free(temp);

    result_list->size--;
}

void get(list* result_list, int position)
{
    node* temp;
    temp = result_list->head;

    if (result_list->size - 2 < position)
    {
        printf("invalid position\n");
        return;
    }

    for (int i = 0; i < position; i++)
        temp = temp->next;

    printf("%c\n", temp->data);
}

void print(list* result_list)
{
    node* temp;
    temp = result_list->head;

    for (int i = 0; i < result_list->size - 2; i++)
    {
        temp = temp->next;
        printf("%c", temp->data);
    }
    printf("\n");
}
