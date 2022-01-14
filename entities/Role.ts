export enum Role {
    USER = "USER",
    ADMIN = "ADMIN"
}

export const toRole = (input: string) => {
    if (input === "USER") {
        return Role.USER
    }
    
    return Role.ADMIN
}