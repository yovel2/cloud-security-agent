import matplotlib.pyplot as plt
import numpy as np

def generate_average_graph():
    """
    Generates a professional bar chart comparing average model accuracy
    based on manually provided data points.
    """
    # =========================================================================
    # USER CONFIGURATION: ENTER YOUR AVERAGED RESULTS HERE
    # =========================================================================
    # Replace the numbers below with the average accuracy you calculated
    # format -> "Model Name": Percentage
    
    average_results = {
        "llama-3.3-70b-versatile": 85.00,  # <-- Enter average here
        "llama-3.1-8b-instant": 75.00,     # <-- Enter average here
        "gemini-3.1-flash-lite": 85.00,    # <-- Enter average here
        "llama-4-scout-17b": 80.00        # <-- Enter average here
    }
    
    # =========================================================================

    # Extract data for plotting
    models = list(average_results.keys())
    accuracies = list(average_results.values())

    # ---------------------------------------------------------
    # PLOTTING THE ACCURACY BAR CHART
    # ---------------------------------------------------------
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Create the bars with a professional dark blue/slate color
    bars = ax.bar(models, accuracies, color='#2c3e50', width=0.5, edgecolor='black')

    # Add text, titles, and custom labels
    ax.set_ylabel('Average Accuracy (%)', fontsize=12, fontweight='bold')
    ax.set_title('Cloud Security Agent: Average LLM Triage Accuracy', pad=20, fontsize=16, fontweight='bold')
    
    # Set Y-axis to go slightly above 100 so the top labels don't get cut off
    ax.set_ylim(0, 115) 
    
    # Professional touches: horizontal grid lines behind the bars
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)

    # X-axis formatting
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels(models, rotation=15, ha="right", fontsize=11)

    # Attach a text label directly above each bar displaying its numerical percentage
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.2f}%',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 5),  # 5 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontweight='bold', fontsize=11)

    # Adjust layout to prevent label cropping
    fig.tight_layout()

    # Save the graph as a high-resolution PNG image
    output_filename = "cloud_security_agent_average_accuracy.png"
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"[+] Success: Average accuracy graph generated and saved to {output_filename}")

if __name__ == "__main__":
    generate_average_graph()
