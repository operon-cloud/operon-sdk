using System.Collections.Concurrent;
using System.Collections.Generic;
using Operon.Sdk.Models;

namespace Operon.Sdk.Catalog;

internal sealed class CatalogRegistry
{
    private readonly ConcurrentDictionary<string, InteractionSummary> _interactions = new();
    private readonly ConcurrentDictionary<string, ParticipantSummary> _participants = new();

    public void UpdateInteractions(IEnumerable<InteractionSummary> interactions)
    {
        _interactions.Clear();
        foreach (var interaction in interactions)
        {
            _interactions[interaction.Id] = interaction;
        }
    }

    public void UpdateParticipants(IEnumerable<ParticipantSummary> participants)
    {
        _participants.Clear();
        foreach (var participant in participants)
        {
            _participants[participant.Id] = participant;
        }
    }

    public bool TryGetInteraction(string interactionId, out InteractionSummary? summary)
        => _interactions.TryGetValue(interactionId, out summary);

    public IReadOnlyCollection<InteractionSummary> Interactions
        => _interactions.Values as IReadOnlyCollection<InteractionSummary> ?? new List<InteractionSummary>(_interactions.Values);

    public IReadOnlyCollection<ParticipantSummary> Participants
        => _participants.Values as IReadOnlyCollection<ParticipantSummary> ?? new List<ParticipantSummary>(_participants.Values);
}
