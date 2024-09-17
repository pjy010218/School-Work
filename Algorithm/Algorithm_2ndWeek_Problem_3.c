#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>
#include<time.h>

void InsertionSort(int arr[], int N);
void ReverseInsertionSort(int arr[], int N);
void SelectionSort(int arr[], int N);
void swap(int* a, int* b);

int main()
{
	int N;
	scanf("%d", &N);

	int* arrA = (int*)malloc(sizeof(int) * N);
	int* arrB = (int*)malloc(sizeof(int) * N);

	for (int i = 0; i < N; i++)
	{
		srand(time(NULL));
		arrA[i], arrB[i] = rand();
	}

	LARGE_INTEGER ticksPerSec;
	LARGE_INTEGER start, end, diff;

	QueryPerformanceFrequency(&ticksPerSec);
	QueryPerformanceCounter(&start);
	SelectionSort(arrA, N);
	QueryPerformanceCounter(&end);

	diff.QuadPart = end.QuadPart - start.QuadPart;
	printf("%.12fms\n", ((double)diff.QuadPart / (double)ticksPerSec.QuadPart));

	QueryPerformanceFrequency(&ticksPerSec);
	QueryPerformanceCounter(&start);
	InsertionSort(arrB, N);
	QueryPerformanceCounter(&end);

	diff.QuadPart = end.QuadPart - start.QuadPart;
	printf("%.12fms\n", ((double)diff.QuadPart / (double)ticksPerSec.QuadPart));

}


void InsertionSort(int arr[], int N)
{
	int MovingInt;
	for (int i = 0; i < N; i++)
	{
		int j;
		MovingInt = arr[i];

		for (j = i - 1; j >= 0 && arr[j] > MovingInt; j--)
		{
			arr[j + 1] = arr[j];
			if (arr[j] < MovingInt)
				break;
		}
		arr[j + 1] = MovingInt;
	}
}

void ReverseInsertionSort(int arr[], int N)
{
	int MovingInt;
	for (int i = 1; i < N; i++)
	{
		int j;
		MovingInt = arr[i];

		for (j = i - 1; j >= 0 && arr[j] < MovingInt; j--)
		{
			arr[j + 1] = arr[j];
			if (arr[j] > MovingInt)
				break;
		}
		arr[j + 1] = MovingInt;
	}
}

void SelectionSort(int arr[], int N)
{
	int MaxIntPosition;
	for (int i = N - 1; i > 0; i--)
	{
		MaxIntPosition = i;
		for (int j = i - 1; j >= 0; j--)
		{
			if (arr[j] > arr[MaxIntPosition])
				MaxIntPosition = j;
		}

		swap(&arr[MaxIntPosition], &arr[i]);
	}
}

void swap(int* a, int* b)
{
	int temp = *a;
	*a = *b;
	*b = temp;
}
