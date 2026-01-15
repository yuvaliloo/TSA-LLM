from src.EnsemblePipeline import MalwareEnsemble

agent = MalwareEnsemble()
result = agent.predict("data/dataset_final/test/malware/some_virus.docm")

print(result)