import matplotlib.pyplot as plt
import numpy as np
import math

# Définir la fonction
def bits_necessaires(x):
    return int(256 - ((256 * ((x-1)/x)) - (0.5 * math.log2(x)))) + 1

# Plage de x : nombre de messages
x_vals = np.arange(2, 500)  # par exemple de 1 à 50 messages
y_vals = [bits_necessaires(x) for x in x_vals]

# Création du graphe
plt.figure(figsize=(10,6))
plt.plot(x_vals, y_vals, marker='o', linestyle='-', color='blue', label="Bit leakage")

# Labels et titre
plt.xscale("log")
plt.grid(True)
plt.legend()
plt.tight_layout()

# Labels et titre
plt.xlabel("Number of signatures obtained (log scale)")
plt.ylabel("Bit leakage necessary (side-channels, biais, backdoor, etc.)")
plt.title("Bit leakage necessary to break ECDSA with HNP & LLL (ECC order ~ 2^{256})")
plt.grid(True, which="both", linestyle="--", linewidth=0.5)  # grille adaptée aux axes log
plt.legend()
plt.tight_layout()


# Affichage
plt.savefig("plot_bias.png", dpi=300)
plt.show()