import type { InteractionSummary, ParticipantSummary } from '../types.js';

export interface InteractionMetadata {
  id: string;
  workstreamId: string;
  workstreamName?: string;
  name?: string;
  description?: string;
  status?: string;
  sourceParticipantId: string;
  targetParticipantId: string;
  sourceDid?: string;
  targetDid?: string;
  type?: string;
  actor?: string;
  states?: string[];
  roiClassification?: string;
  roiCost?: number;
  roiTime?: number;
}

export interface ParticipantMetadata {
  id: string;
  did: string;
  name?: string;
  status?: string;
  customerId?: string;
  workstreamId?: string;
  workstreamName?: string;
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
      this.interactions.set(item.id, {
        ...item,
        states: item.states ? [...item.states] : undefined
      });
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
    return metadata
      ? {
          ...metadata,
          states: metadata.states ? [...metadata.states] : undefined
        }
      : undefined;
  }

  interactionsList(): InteractionSummary[] {
    return Array.from(this.interactions.values()).map((item) => ({
      id: item.id,
      workstreamId: item.workstreamId,
      channelId: item.workstreamId,
      workstreamName: item.workstreamName,
      name: item.name,
      description: item.description,
      status: item.status,
      sourceParticipantId: item.sourceParticipantId,
      targetParticipantId: item.targetParticipantId,
      sourceDid: item.sourceDid,
      targetDid: item.targetDid,
      type: item.type,
      actor: item.actor,
      states: item.states ? [...item.states] : undefined,
      roiClassification: item.roiClassification,
      roiCost: item.roiCost,
      roiTime: item.roiTime
    }));
  }

  participantsList(): ParticipantSummary[] {
    return Array.from(this.participants.values()).map((item) => ({
      id: item.id,
      did: item.did,
      name: item.name,
      status: item.status,
      customerId: item.customerId,
      workstreamId: item.workstreamId,
      channelId: item.workstreamId,
      workstreamName: item.workstreamName
    }));
  }
}
