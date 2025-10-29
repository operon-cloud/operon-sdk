import type { InteractionSummary, ParticipantSummary } from '../types.js';

export interface InteractionMetadata {
  id: string;
  channelId: string;
  sourceParticipantId: string;
  targetParticipantId: string;
  sourceDid?: string;
  targetDid?: string;
}

export interface ParticipantMetadata {
  id: string;
  did: string;
}

/**
 * In-memory cache for interaction and participant metadata.
 */
export class Registry {
  private readonly interactions = new Map<string, InteractionMetadata>();
  private readonly participants = new Map<string, ParticipantMetadata>();

  replaceInteractions(items: InteractionMetadata[]): void {
    this.interactions.clear();
    for (const item of items) {
      if (!item.id) {
        continue;
      }
      this.interactions.set(item.id, { ...item });
    }
  }

  replaceParticipants(items: ParticipantMetadata[]): void {
    this.participants.clear();
    for (const item of items) {
      if (!item.id) {
        continue;
      }
      this.participants.set(item.id, { ...item });
    }
  }

  interaction(id: string): InteractionMetadata | undefined {
    const metadata = this.interactions.get(id);
    return metadata ? { ...metadata } : undefined;
  }

  interactionsList(): InteractionSummary[] {
    return Array.from(this.interactions.values()).map((item) => ({
      id: item.id,
      channelId: item.channelId,
      sourceParticipantId: item.sourceParticipantId,
      targetParticipantId: item.targetParticipantId,
      sourceDid: item.sourceDid,
      targetDid: item.targetDid
    }));
  }

  participantsList(): ParticipantSummary[] {
    return Array.from(this.participants.values()).map((item) => ({
      id: item.id,
      did: item.did
    }));
  }
}
