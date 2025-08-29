/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <thread>
#include <unistd.h>
#include <vector>
#include <thread>

const int WAITTIME = 200000;
const int BUFSIZE = 1048576;

void Func10()
{
    void *temp = nullptr;
    // try for each thread times
    while (true) {
        temp = malloc(BUFSIZE);
        usleep(WAITTIME);
        if (temp != nullptr) {
            free(temp);
            temp = nullptr;
        }
    }
}

void Func9()
{
    Func10();
}

void Func8()
{
    Func9();
}

void Func7()
{
    Func8();
}

void Func6()
{
    Func7();
}

void Func5()
{
    Func6();
}

void Func4()
{
    Func5();
}

void Func3()
{
    Func4();
}

void Func2()
{
    Func3();
}

void Func1()
{
    Func2();
}

void ThreadFunction()
{
    Func1();
}

int main(const int argc, const char *argv[])
{
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) { // 10: create 10 threads
        threads.push_back(std::thread(ThreadFunction));
        usleep(WAITTIME);
    }
    for (auto& th : threads) {
        th.join();
    }
    return 0;
};
