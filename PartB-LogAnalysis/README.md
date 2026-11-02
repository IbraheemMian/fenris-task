# fenris-task

First install the requirments

    - python -m pip install -r requirements.txt

Then run the application using

    - python main.py app_logs.txt --model qwen3:1.7b --out output/
    - python main.py app_logs.txt --prompt v1 --out output/
    - python main.py app_logs.txt --model qwen3:1.7b --prompt v1 --out output/

## Evaluate prompts

Preparing

    - python eval.py app_logs.txt --prepare


Running

    - python eval.py app_logs.txt --model qwen3:1.7b
   
## Tests (model-free)
```powershell
python -m pytest -q
```