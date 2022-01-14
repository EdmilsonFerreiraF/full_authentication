export enum Role {
    USER = "USER",
    ADMIN = "ADMIN"
}

export const toRole = (input: string) => {
    if (input === "USER") {
        return Role.USER
    } else if (input === "ADMIN") {
        return Role.ADMIN
    } else {
        throw new Error('Invalid user role');
    }
}

export const roleToString = (input: Role) => {
    if (input === Role.USER) {
        return "USER"
    } else if (input === Role.ADMIN) {
        return "ADMIN"
    } else {
        throw new Error('Invalid user role');
    }
}

