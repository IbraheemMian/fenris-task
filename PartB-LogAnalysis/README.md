# fenris-task

First install the requirments

    - python -m pip install -r requirements.txt

Then run the application using

    - python main.py app_logs.txt --model qwen3:1.7b --out output/

Preparing the evaluations

    - python eval.py app_logs.txt --prepare

Running the evaluations

    - python eval.py app_logs.txt --model qwen3:1.7b
    
