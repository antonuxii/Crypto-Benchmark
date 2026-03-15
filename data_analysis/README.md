## Folder Structure
* `final_logs/`: Contains the logs that were generated from running our benchmark, and those used for the data analysis performed in the final Thesis submission. Each file in this folder was renamed in the nomenclature `CIPHER_Nr_A` where `N` is the number of rounds and `A` names the batch number. Then, to refer to a particular sample we use the naming convention `CIPHER_Nr_A_B` where `B` furhter specifies the sample number within that batch.
* `pilots.ipynb`: The jupyter notebook used to generate the graphs and data analysis for the pilot phase of the experiment runs
* `main.ipynb`: The jupyter notebook used to generate the graphs and data analysis for the full benchmark
* `tests/`: Contains scripts were the code produced by the model across runs was extracted and run independently.
