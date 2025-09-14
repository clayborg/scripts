#!/usr/bin/env python3
import file_extract
import sys

class Header:
    chunk_id = 'MThd'
    def __init__(self, format=1, num_tracks=0, divisions=480):
        self.format = format
        self.num_tracks = num_tracks
        self.divisions = divisions

    @classmethod
    def decode(cls, data):
        format = data.get_uint16()
        num_tracks = data.get_uint16()
        divisions = data.get_uint16()
        return Header(format, num_tracks, divisions)

    def encode(self, data):
        data.put_c_string(self.chunk_id, null_terminate=False)
        data.put_uint32(6) # Size of a header chunk data is 6
        data.put_uint16(self.format)
        data.put_uint16(self.num_tracks)
        data.put_uint16(self.divisions)

    def dump(self, f=sys.stdout):
        f.write("%s: format=%u, num_tracks=%u divisions=%u\n" % (self.chunk_id, self.format, self.num_tracks, self.divisions))

class Status:
    def __init__(self, type, channel):
        self.type = type
        self.channel = channel

    @classmethod
    def decode(cls, data, running_status):
        status = data.get_uint8()
        if status & 0x80:
            if status & 0xf0 == 0xf0:
                return Status(status, None)
            return Status(status >> 4, status & 0x0f)
        # We need to use the running status as the status bytes must have the
        # bit 7 set to 1. If it ins't set to 1, then it uses the running status.
        data.seek(data.tell()-1)
        return running_status

    def encode(self, data):
        if self.channel is None:
            data.put_uint8(self.type)
        else:
            data.put_uint8(self.type << 4 | self.channel)

    def dump(self, f=sys.stdout):
        f.write(f'type={self.type:x}, channel={self.channel}')

class NoteOffEvent:
    status_type = 8
    def __init__(self, delta_t, midi_channel, note, velocity):
        self.event = Event(delta_t, Status(self.status_type, midi_channel))
        self.note = note
        self.velocity = velocity

    @classmethod
    def decode(cls, event, data):
        return cls(delta_t = event.delta_t,
                   midi_channel = event.status.channel,
                   note = data.get_uint8(),
                   velocity = data.get_uint8())

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.note)
        data.put_uint8(self.velocity)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'Event -- Note Off: note={self.note}, velocity={self.velocity}\n')

class NoteOnEvent:
    status_type = 9
    def __init__(self, delta_t, midi_channel, note, velocity):
        self.event = Event(delta_t, Status(self.status_type, midi_channel))
        self.note = note
        self.velocity = velocity

    @classmethod
    def decode(cls, event, data):
        return cls(delta_t = event.delta_t,
                   midi_channel = event.status.channel,
                   note = data.get_uint8(), # Note number
                   velocity = data.get_uint8()) # Note velocity

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.note)
        data.put_uint8(self.velocity)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'Event -- Note On : note={self.note}, velocity={self.velocity}\n')


class MetaEventTrackName:
    meta_type = 0x3
    def __init__(self, delta_t, track_name):
        self.event = Event(delta_t, Status(0xff, None))
        self.track_name = track_name

    @classmethod
    def decode(cls, event, data):
        track_name = data.get_fixed_length_c_string(data.get_size())
        return cls(event.delta_t, track_name)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(len(self.track_name)) # Length of data for meta events
        data.put_c_string(self.track_name, null_terminate=False)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}: "{self.track_name}"\n')


class MetaEventInstrumentName:
    meta_type = 0x4
    def __init__(self, delta_t, name):
        self.event = Event(delta_t, Status(0xff, None))
        self.name = name

    @classmethod
    def decode(cls, event, data):
        name = data.get_fixed_length_c_string(data.get_size())
        return cls(event.delta_t, name)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(len(self.name)) # Length of data for meta events
        data.put_c_string(self.name, null_terminate=False)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}: "{self.name}"\n')


class MetaEventMidiChannelPrefix:
    '''
    MIDI Channel Prefix

    FF 20 01 cc

    cc is a byte specifying the MIDI channel (0-15).

    This optional event is used to associate any subsequent SysEx and Meta
    events with a particular MIDI channel, and will remain in effect until the
    next MIDI Channel Prefix Meta event or the next MIDI event.

    It's use is particularly relevant in format 0 MIDI files, where
    multi-channel data is contained in the single MTrk chunk. E.g. if you want
    to use Instrument Name Meta events then you can either include the MIDI
    channel (textually) within these events, or you could precede them with a
    MIDI Channel Prefix Meta event, so that it is clear which MIDI channel each
    Instrument Name event refers to.

    It is also useful when converting a MIDI file from format 0 to 1, and back
    again, as any association between non MIDI events and a particular MIDI
    channel can be retained. E.g. in a format 1 MIDI file, where each track
    contains data for a single MIDI channel (that's not a neccessity, it's just
    a convention) there will be various SysEx and Meta events distributed
    amongst the various tracks and hence associated with the same MIDI channel
    as the MIDI events within each track. Thus when converting to a format 0
    MIDI file, the SysEx and Meta events from each track can be clustered
    together and preceded by an appropriate MIDI Channel Prefix event. When
    converting back to a format 1 MIDI file, these clusters of SysEx and Meta
    events can be placed in separate tracks along with their associated MIDI
    events, thus restoring the original structure.
    '''
    meta_type = 0x20
    def __init__(self, delta_t, channel):
        self.event = Event(delta_t, Status(0xff, None))
        self.channel = channel

    @classmethod
    def decode(cls, event, data):
        channel = data.get_uint8()
        return cls(event.delta_t, channel)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(1) # Length of data for meta events
        data.put_uint8(self.channel)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}: channel={self.channel}\n')


class MetaEventEndOfTrack:
    meta_type = 0x2f
    def __init__(self, delta_t):
        self.event = Event(delta_t, Status(0xff, None))

    @classmethod
    def decode(cls, event, data):
        return cls(delta_t = event.delta_t)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(0) # Length of data for meta events

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}\n')


class MetaEventTempo:
    meta_type = 0x51
    def __init__(self, delta_t, tempo):
        self.event = Event(delta_t, Status(0xff, None))
        self.tempo = tempo

    @classmethod
    def decode(cls, event, data):
        tempo = data.get_uint24()
        return cls(event.delta_t, tempo)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(3) # Length of data for meta events
        # Write the tempo out as a big endian 24 bit value
        data.put_uint24(self.tempo)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}: tempo={self.tempo} usec/quarter note ({60000000/self.tempo} bpm)\n')

class MetaEventSMPTEOffset:
    '''
    SMPTE Offset

FF 54 05 hr mn se fr ff

hr is a byte specifying the hour, which is also encoded with the SMPTE format (frame rate), just as it is in MIDI Time Code, i.e. 0rrhhhhh, where :
rr = frame rate : 00 = 24 fps, 01 = 25 fps, 10 = 30 fps (drop frame), 11 = 30 fps (non-drop frame)
hhhhh = hour (0-23)
mn se are 2 bytes specifying the minutes (0-59) and seconds (0-59), respectively.
fr is a byte specifying the number of frames (0-23/24/28/29, depending on the frame rate specified in the hr byte).
ff is a byte specifying the number of fractional frames, in 100ths of a frame (even in SMPTE-based tracks using a different frame subdivision, defined in the MThd chunk).
This optional event, if present, should occur at the start of a track, at time = 0, and prior to any MIDI events. It is used to specify the SMPTE time at which the track is to start.

For a format 1 MIDI file, a SMPTE Offset Meta event should only occur within the first MTrk chunk.
    '''
    meta_type = 0x54
    def __init__(self, delta_t, hr, mn, se, fr, ff):
        self.event = Event(delta_t, Status(0xff, None))
        self.hr = hr
        self.mn = mn
        self.se = se
        self.fr = fr
        self.ff = ff

    @classmethod
    def decode(cls, event, data):
        hr = data.get_uint8()
        mn = data.get_uint8()
        se = data.get_uint8()
        fr = data.get_uint8()
        ff = data.get_uint8()
        return cls(event.delta_t, hr, mn, se, fr, ff)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(5) # Length of data for meta events
        # Write the tempo out as a big endian 24 bit value
        data.put_uint8(self.hr)
        data.put_uint8(self.mn)
        data.put_uint8(self.se)
        data.put_uint8(self.fr)
        data.put_uint8(self.ff)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}: hr={self.hr} mn={self.mn} se={self.se} fr={self.fr} ff={self.ff}\n')



class MetaEventTimeSignature:
    '''
    Time Signature

    FF 58 04 nn dd cc bb

    nn is a byte specifying the numerator of the time signature (as notated).

    dd is a byte specifying the denominator of the time signature as a negative
    power of 2 (i.e. 2 represents a quarter-note, 3 represents an eighth-note,
    etc).

    cc is a byte specifying the number of MIDI clocks between metronome clicks.

    bb is a byte specifying the number of notated 32nd-notes in a MIDI
    quarter-note (24 MIDI Clocks). The usual value for this parameter is 8,
    though some sequencers allow the user to specify that what MIDI thinks of as
    a quarter note, should be notated as something else.
    '''
    meta_type = 0x58
    def __init__(self, delta_t, nn, dd, cc=24, bb=8):
        self.event = Event(delta_t, Status(0xff, None))
        self.nn = nn
        self.dd = dd
        self.cc = cc
        self.bb = bb

    @classmethod
    def decode(cls, event, data):
        nn = data.get_uint8()
        dd = data.get_uint8()
        cc = data.get_uint8()
        bb = data.get_uint8()
        return cls(event.delta_t, nn, dd, cc, bb)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(4) # Length of data for meta events
        # Write the tempo out as a big endian 24 bit value
        data.put_uint8(self.nn)
        data.put_uint8(self.dd)
        data.put_uint8(self.cc)
        data.put_uint8(self.bb)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}: signature={self.nn}/{2 ** self.dd} cc={self.cc} bb={self.bb}\n')

class MetaEventKeySignature:
    '''
    Key Signature

    FF 59 02 sf mi

    sf is a byte specifying the number of flats (-ve) or sharps (+ve) that
    identifies the key signature (-7 = 7 flats, -1 = 1 flat, 0 = key of C, 1 = 1
    sharp, etc).

    mi is a byte specifying a major (0) or minor (1) key.

    For a format 1 MIDI file, Key Signature Meta events should only occur within
    the first MTrk chunk.
    '''
    meta_type = 0x59
    sf_to_key_name = {
        0: ['C','A'],
        1: ['G','E'],
        2: ['D','B'],
        3: ['A','F#'],
        4: ['E','C#'],
        5: ['B','G#'],
        6: ['F#','Eb'],
        7: ['C#','Bb'],
        -1: ['F','D'],
        -2: ['Bb','G'],
        -3: ['Eb','C'],
        -4: ['Ab','F'],
        -5: ['Db','Bb'],
        -6: ['Gb','Eb'],
        -7: ['Cb','G#'],
    }
    def __init__(self, delta_t, sf, mi):
        self.event = Event(delta_t, Status(0xff, None))
        self.sf = sf
        self.mi = mi

    @classmethod
    def create_from_key_name(cls, key_name):
        minor = key_name.endswith('m')
        if minor:
            mi = 1
            root_note = key_name[0:-1]
        else:
            mi = 0
            root_note = key_name
        index = 1 if minor else 0
        for sf in cls.sf_to_key_name:
            if cls.sf_to_key_name[sf][index] == root_note:
                return MetaEventKeySignature(delta_t=0, sf=sf, mi=mi)
        message = f'invalid key name "{key_name}"'
        raise ValueError(message)

    @classmethod
    def decode(cls, event, data):
        sf = data.get_uint8()
        mi = data.get_uint8()
        return cls(event.delta_t, sf, mi)

    def encode(self, data):
        self.event.encode(data)
        data.put_uint8(self.meta_type)
        data.put_uint8(2) # Length of data for meta events
        # Write the tempo out as a big endian 24 bit value
        data.put_uint8(self.sf)
        data.put_uint8(self.mi)

    def get_key_name(self):
        if self.mi:
            mi_str = 'minor'
        else:
            mi_str = 'major'
        return f'{self.sf_to_key_name[self.sf][self.mi]} {mi_str}'

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'{self.__class__.__name__}: {self.get_key_name()}\n')

class MetaEvent:
    type_to_class = {
        MetaEventTrackName.meta_type: MetaEventTrackName,
        MetaEventInstrumentName.meta_type: MetaEventInstrumentName,
        MetaEventMidiChannelPrefix.meta_type: MetaEventMidiChannelPrefix,
        MetaEventEndOfTrack.meta_type: MetaEventEndOfTrack,
        MetaEventTempo.meta_type: MetaEventTempo,
        MetaEventSMPTEOffset.meta_type: MetaEventSMPTEOffset,
        MetaEventTimeSignature.meta_type: MetaEventTimeSignature,
        MetaEventKeySignature.meta_type: MetaEventKeySignature,
    }

    status_type = 0xff
    def __init__(self, event, meta_type, data):
        self.event = event
        self.meta_type = meta_type
        self.data = data

    @classmethod
    def decode(cls, event, data):
        meta_type = data.get_uint8()
        length = data.get_midi_vlq()
        meta_data = data.read_data(length)
        if meta_type not in cls.type_to_class:
            return MetaEvent(event, meta_type, meta_data)
        return cls.type_to_class[meta_type].decode(event, meta_data)

    def dump(self, f=sys.stdout):
        self.event.dump(f)
        f.write(f'Meta Event: meta_type=0x{self.meta_type:x}, length={self.data.get_size()}\n')

class Event:
    type_to_class = {
        NoteOffEvent.status_type: NoteOffEvent,
        NoteOnEvent.status_type: NoteOnEvent,
        MetaEvent.status_type: MetaEvent
    }

    def __init__(self, delta_t, status, offset = None):
        self.delta_t = delta_t
        self.status = status
        self.offset = offset

    @classmethod
    def decode(cls, data, running_status):
        offset = data.tell()
        delta_t = data.get_midi_vlq()
        status = Status.decode(data, running_status)
        event = Event(delta_t, status, offset)
        if event.status.type not in cls.type_to_class:
            print(f"Unsupported event nibble {event.status.type}")
            return None
        event_class = cls.type_to_class[event.status.type]
        return event_class.decode(event, data)

    def encode(self, data):
        data.put_midi_vlq(self.delta_t)
        self.status.encode(data)

    def dump(self, f=sys.stdout):
        if self.offset is not None:
            f.write(f'0x{self.offset:8x}: ')
        f.write(f'{self.delta_t:5d} ');

class Track:
    chunk_id = 'MTrk'
    def __init__(self, events = None):
        if events is None:
            self.events = []
        else:
            self.events = events

    @classmethod
    def decode(cls, data):
        running_status = None
        events = []
        data_size = data.get_size()
        data.seek(0)
        while data.tell() < data_size:
            event = Event.decode(data, running_status)
            if event is None:
                break
            events.append(event)
            running_status = event.event.status
        return Track(events)

    def encode(self, data):
        data.put_c_string(self.chunk_id, null_terminate=False)
        size_offset = data.tell()
        data.put_uint32(0) # Emit a size of zero, we will fix this up.
        data_offset = data.tell()
        for event in self.events:
            event.encode(data)
        data_size = data.tell() - data_offset
        if data_size > 0:
            data.fixup_uint_size(4, data_size, size_offset)

    def set_name(self, name):
        '''Set the track name.'''
        self.events.append(MetaEventTrackName(delta_t=0, track_name=name))

    def set_instrument_name(self, name):
        '''Set the track's instrument name.'''
        self.events.append(MetaEventInstrumentName(delta_t=0, name=name))

    def set_tempo(self, bpm):
        '''Set the tempo from beats per minite.'''
        self.events.append(MetaEventTempo(delta_t=0, tempo=int(60_000_000/bpm)))

    def set_key_signature(self, key_name: str):
        '''Set the major key signature. Examples include "C", "G#", "Am" or "G#m".

        The key name starts with a capitol root note letter followed by an
        optional '#' for sharp or 'b' for flat. The key name is suffixed with
        'm' to indicate a minor key.
        '''
        self.events.append(MetaEventKeySignature.create_from_key_name(key_name))

    def set_time_signature(self, top: int, bottom: int):
        '''Set the time signature from the top and bottom number of the time signature.'''
        dd = 1
        while True:
            curr_bottom = 2 ** dd
            if curr_bottom == bottom:
                break
            if curr_bottom > bottom:
                message = f'Invalid time signature denominator {bottom}. The value must be a power of 2.'
                raise ValueError(message)
            dd += 1
        self.events.append(MetaEventTimeSignature(delta_t=0, nn=top, dd=dd))

    def dump(self, f=sys.stdout):
        f.write(f"{self.chunk_id}:\n")
        for (i, event) in enumerate(self.events):
            f.write(f'event[{i:3}] ')
            event.dump(f)


class Chunk:
    # A map of chunk identifier to the class.
    chunk_id_to_class = {
        Header.chunk_id: Header,
        Track.chunk_id: Track
    }
    def __init__(self, data = None):
        self.offset = None
        self.id = None
        self.size = None
        self.data = None
        if data is not None:
            self.offset = data.tell()
            self.id = data.get_fixed_length_c_string(4)
            self.size = data.get_uint32()
            if self.size > 0:
                offset = data.tell()
                self.data = data.read_data(self.size)

    def is_valid(self):
        if self.offset is not None:
            if self.id in [Header.chunk_id, Track.chunk_id]:
                return True
        return False

    def dump(self, f=sys.stdout):
        if self.offset is None:
            f.write("'%s'" % (self.id))
        else:
            f.write("%#8.8x: '%s' <%u> " % (self.offset, self.id, self.size))

    @classmethod
    def decode(cls, data):
        chunk = Chunk(data)
        if chunk.is_valid():
            chunk_class = cls.chunk_id_to_class[chunk.id]
            return chunk_class.decode(chunk.data)
        return None

class File:
    def __init__(self, data = None):
        self.chunks = []
        if data is None:
            self.chunks.append(Header())
        else:
            while True:
                chunk = Chunk.decode(data)
                if chunk is None:
                    break
                self.chunks.append(chunk)

    def add_track(self):
        self.chunks.append(Track())
        return self.chunks[-1]

    def dump(self, f=sys.stdout):
        for chunk in self.chunks:
            chunk.dump(f)

    def save(self, path):
        data = file_extract.FileEncode(byte_order='big')
        header = self.chunks[0]
        header.num_tracks = len(self.chunks)-1
        if header.num_tracks == 1:
            header.format = 0
        else:
            header.format = 1
        for chunk in self.chunks:
            chunk.encode(data)
        with open(path, "wb") as f:
            f.write(data.file.getvalue())



def main(args):
    if args:
        for path in args:
            file = open(path, 'rb')
            data = file_extract.FileExtract(file, 'big', addr_size=4, offset_size=4)
            midi_file = File(data)
            midi_file.dump()
    else:
        midi_file = File()
        track1 = midi_file.add_track()
        track1.set_tempo(120.0)
        track1.set_name("midi.py test file")
        track1.set_instrument_name('Grand Piano')
        track1.set_time_signature(4, 4)
        track1.set_key_signature('Am')
        track1.events.append(NoteOnEvent(delta_t=0, midi_channel=0, note=60, velocity=100))
        track1.events.append(NoteOffEvent(delta_t=480*2, midi_channel=0, note=60, velocity=0))
        track1.events.append(NoteOnEvent(delta_t=0, midi_channel=0, note=62, velocity=100))
        track1.events.append(NoteOffEvent(delta_t=480, midi_channel=0, note=62, velocity=0))
        track1.events.append(NoteOnEvent(delta_t=0, midi_channel=0, note=64, velocity=100))
        track1.events.append(NoteOffEvent(delta_t=240, midi_channel=0, note=64, velocity=0))
        track1.events.append(MetaEventEndOfTrack(delta_t=0))
        midi_file.dump()
        midi_file.save('/Users/gclayton/Documents/midi/save.mid')


if __name__ == '__main__':
    main(sys.argv[1:])
